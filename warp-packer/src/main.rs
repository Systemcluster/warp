extern crate clap;
extern crate dirs;
extern crate flate2;
#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate tar;
extern crate tempdir;

use clap::{App, AppSettings, Arg};
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io;
use std::io::copy;
use std::io::Write;
use std::iter;
use std::path::Path;
use std::process;
use tempdir::TempDir;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
const VERSION: &str = env!("CARGO_PKG_VERSION");

const RUNNER_EXEC_MAGIC: &[u8] = b"tVQhhsFFlGGD3oWV4lEPST8I8FEPP54IM0q7daes4E1y3p2U2wlJRYmWmjPYfkhZ0PlT14Ls0j8fdDkoj33f2BlRJavLj3mWGibJsGt5uLAtrCDtvxikZ8UX2mQDCrgE\0";
const RUNNER_NAME_MAGIC: &[u8] = b"4XMKSjaEZN9eC9LlptwBG3A7ysWD0L5hNK6tNrOiEd0p76Fu3ImTpcUjgMoWGyO1JS0Db2gqmlVEH7rW12vSmLN8x6M1GS0nE5xnL2QMOYYuMqI0CobsfzQYXKsUsJsj\0";
const RUNNER_UID_MAGIC: &[u8] = b"DR1PWsJsM6KxNbng9Y38\0";

static RUNNER_USE_TEMP_DIR_MAGIC: &[u8] = b"hCq8W43N1AcLKGqpa2rj\0";
static RUNNER_USE_ALTERNATIVE_PATH_MAGIC: &[u8] = b"Wh81O21Yrq2hGxJAKB1P\0";
static RUNNER_SET_CURRENT_DIR_MAGIC: &[u8] = b"RfZTmxJoQB17TQtBJqux\0";

#[cfg(all(feature = "target-native", target_family = "windows"))]
const RUNNER_NATIVE: &[u8] = include_bytes!("../../target/release/warp-runner.exe");
#[cfg(all(feature = "target-native", not(target_family = "windows")))]
const RUNNER_NATIVE: &[u8] = include_bytes!("../../target/release/warp-runner");
#[cfg(feature = "target-linux_x64")]
const RUNNER_LINUX_X64: &[u8] =
    include_bytes!("../../target/x86_64-unknown-linux-gnu/release/warp-runner");
#[cfg(feature = "target-macos_x64")]
const RUNNER_MACOS_X64: &[u8] =
    include_bytes!("../../target/x86_64-apple-darwin/release/warp-runner");
#[cfg(feature = "target-windows_x64")]
const RUNNER_WINDOWS_X64: &[u8] =
    include_bytes!("../../target/x86_64-pc-windows-gnu/release/warp-runner.exe");

lazy_static! {
    static ref RUNNER_BY_ARCH: HashMap<&'static str, &'static [u8]> = {
        let mut m = HashMap::new();
        #[cfg(feature = "target-native")]
        m.insert("native", RUNNER_NATIVE);
        #[cfg(feature = "target-linux_x64")]
        m.insert("linux-x64", RUNNER_LINUX_X64);
        #[cfg(feature = "target-macos_x64")]
        m.insert("macos-x64", RUNNER_MACOS_X64);
        #[cfg(feature = "target-windows_x64")]
        m.insert("windows-x64", RUNNER_WINDOWS_X64);
        m
    };
}

/// Print a message to stderr and exit with error code 1
macro_rules! bail {
    () => (process::exit(1));
    ($($arg:tt)*) => ({
        eprint!("{}\n", format_args!($($arg)*));
        process::exit(1);
    })
}

fn patch_runner(
    arch: &str,
    exec_name: &str,
    target_name: &str,
    uid: &str,
    use_temp_dir: &str,
    use_alternate_path: &str,
    set_working_directory: &str,
) -> io::Result<Vec<u8>> {
    // Read runner executable in memory
    let runner_contents = RUNNER_BY_ARCH.get(arch).unwrap();
    let mut buf = runner_contents.to_vec();

    write_magic(&mut buf, RUNNER_UID_MAGIC, uid);
    write_magic(&mut buf, RUNNER_NAME_MAGIC, target_name);
    write_magic(&mut buf, RUNNER_EXEC_MAGIC, exec_name);
    write_magic(&mut buf, RUNNER_USE_TEMP_DIR_MAGIC, use_temp_dir);
    write_magic(
        &mut buf,
        RUNNER_USE_ALTERNATIVE_PATH_MAGIC,
        use_alternate_path,
    );
    write_magic(
        &mut buf,
        RUNNER_SET_CURRENT_DIR_MAGIC,
        set_working_directory,
    );

    Ok(buf)
}

fn write_magic(buf: &mut Vec<u8>, magic: &[u8], new_value: &str) {
    // Set the correct target executable name into the local magic buffer
    let magic_len = magic.len();
    let mut new_magic = vec![0; magic_len];
    new_magic[..new_value.len()].clone_from_slice(new_value.as_bytes());

    // Find the magic buffer offset inside the runner executable
    let mut offs_opt = None;
    for (i, chunk) in buf.windows(magic_len).enumerate() {
        if chunk == magic {
            offs_opt = Some(i);
            break;
        }
    }

    if offs_opt.is_none() {
        bail!("no magic found inside runner");
    }

    // Replace the magic with the new one that points to the target executable
    let offs = offs_opt.unwrap();
    buf[offs..offs + magic_len].clone_from_slice(&new_magic);
}

fn create_tgz(dirs: &Vec<&Path>, out: &Path, compression: u32) -> io::Result<()> {
    let f = fs::File::create(out)?;
    let gz = GzEncoder::new(f, Compression::new(compression));
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);
    for dir in dirs.iter() {
        println!("Compressing input directory {:?}...", dir);
        tar.append_dir_all(".", dir)?;
    }
    Ok(())
}

#[cfg(target_family = "unix")]
fn create_app_file(out: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o755)
        .open(out)
}

#[cfg(target_family = "windows")]
fn create_app_file(out: &Path) -> io::Result<File> {
    if out.is_file() {
        fs::remove_file(out)?;
    }
    fs::OpenOptions::new().create(true).write(true).open(out)
}

fn create_app(runner_buf: &Vec<u8>, tgz_paths: &Vec<&Path>, out: &Path) -> io::Result<()> {
    let mut outf = create_app_file(out)?;
    outf.write_all(runner_buf)?;

    for tgz_path in tgz_paths.iter() {
        let mut tgzf = fs::File::open(tgz_path)?;
        copy(&mut tgzf, &mut outf)?;
    }

    Ok(())
}

fn make_path(path_str: &str) -> &Path {
    let path = Path::new(path_str);
    if fs::metadata(path).is_err() {
        bail!("Cannot access specified input path {:?}", path);
    }
    &path
}

fn check_executable_exists(exec_path: &Path) {
    match fs::metadata(&exec_path) {
        Err(_) => {
            bail!("Cannot find file {:?}", exec_path);
        }
        Ok(metadata) => {
            if !metadata.is_file() {
                bail!("{:?} isn't a file", exec_path);
            }
        }
    }
}

fn generate_uid() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(RUNNER_UID_MAGIC.len() - 1)
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = App::new(APP_NAME)
        .settings(&[AppSettings::ArgRequiredElseHelp, AppSettings::ColoredHelp])
        .version(VERSION)
        .author(AUTHOR.replace(":", ", ").as_ref())
        .about("Create self-contained single binary application")
        .arg(Arg::with_name("arch")
            .short("a")
            .long("arch")
            .value_name("arch")
            .help(&format!("Sets the architecture. Supported: {:?}", RUNNER_BY_ARCH.keys()))
            .display_order(1)
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("input_dir")
            .short("i")
            .long("input_dir")
            .value_name("input_dir")
            .help("Sets the input directories for packing. Might provide multiple directories, but the first must contain the executed application")
            .display_order(2)
            .takes_value(true)
            .required(true)
            .multiple(true)
            .min_values(1))
        .arg(Arg::with_name("input_tgz")
            .short("t")
            .long("input_tgz")
            .value_name("input_tgz")
            .help("Sets additional already packed tar-gzipped files to be included in package. Might provide multiple files. Can be used with --disable_exec_check param if main executable file is in packed file.")
            .display_order(3)
            .takes_value(true)
            .required(false)
            .multiple(true))
        .arg(Arg::with_name("exec")
            .short("e")
            .long("exec")
            .value_name("exec")
            .help("Sets the application executable file name")
            .display_order(4)
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("disable_exec_check")            
            .long("disable_exec_check")
            .help("Disables the check for existence of executable file in target directory. Useful for cases when main executable file is in already packed tgzip file (see input_tgz param)")
            .display_order(5)
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("output")
            .help("Sets the resulting self-contained application file name")
            .display_order(6)
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("unique_id")
            .short("q")
            .long("unique_id")
            .value_name("unique_id")
            .help("Generate unique id for each package build")
            .display_order(7)
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("compression")
            .short("c")
            .long("compression")
            .value_name("compression")
            .help("Sets the compression level")
            .validator(|c: String| {
                if let Ok(u) = c.parse::<u32>() { if u <= 9 { return Ok(()) } }
                Err(String::from("compression level must be a number between 0 and 9"))
            })
            .display_order(8)
            .takes_value(true)
            .required(false)
            .default_value("9"))
        .arg(Arg::with_name("unpack_directory")
            .short("u")
            .long("unpack_directory")
            .value_name("unpack_directory")
            .help("Sets the application unpack directory name. Defaults to the name of the executable.")
            .display_order(10)
            .takes_value(true)
            .required(false)
            .default_value(""))
        .arg(Arg::with_name("use_temp_dir")
            .short("p")
            .long("use_temp_dir")
            .value_name("use_temp_dir")
            .help("Place the application unpack directory inside the %TEMP% directory on Windows")
            .display_order(11)
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("use_alternate_path")
            .short("l")
            .long("use_alternate_path")
            .value_name("use_alternate_path")
            .help("Use <appname>/app instead of warp/packages/<appname> as the application unpack directory tree")
            .display_order(12)
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("set_working_directory")
            .short("w")
            .long("set_working_directory")
            .value_name("set_working_directory")
            .help("Set the working directory of the launched application to the directory of the packed executable")
            .display_order(13)
            .takes_value(false)
            .required(false))
        .get_matches();

    if RUNNER_BY_ARCH.is_empty() {
        bail!("No architectures supported in this build")
    }

    let arch = args.value_of("arch").unwrap();
    if !RUNNER_BY_ARCH.contains_key(&arch) {
        bail!(
            "Unknown architecture specified: {}, supported: {:?}",
            arch,
            RUNNER_BY_ARCH.keys()
        );
    }

    let tmp_dir = TempDir::new(APP_NAME)?;
    let main_tgz = tmp_dir.path().join("input.tgz");
    let main_tgz_path = main_tgz.as_path();

    let input_dirs: Vec<&Path> = args
        .values_of("input_dir")
        .unwrap()
        .map(make_path)
        .collect();

    let input_tgzs: Vec<&Path> = args
        .values_of("input_tgz")
        .unwrap_or(clap::Values::default())
        .map(make_path)
        .chain(iter::once(main_tgz_path))
        .collect();

    let exec_name = args.value_of("exec").unwrap();
    if exec_name.len() >= RUNNER_EXEC_MAGIC.len() {
        bail!("Executable name is too long, please consider using a shorter name");
    }

    let target_name = args.value_of("unpack_directory").unwrap();
    if exec_name.len() >= RUNNER_NAME_MAGIC.len() {
        bail!("Unpack directory name is too long, please consider using a shorter name");
    }

    let do_check_exec_existence = !args.is_present("disable_exec_check");
    if do_check_exec_existence {
        let exec_path = Path::new(input_dirs[0]).join(exec_name);
        check_executable_exists(&exec_path);
    }

    let compression = args
        .value_of("compression")
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let uid = if args.is_present("unique_id") {
        generate_uid()
    } else {
        "".to_string()
    };
    let use_temp_dir = if args.is_present("use_temp_dir") {
        "true".to_string()
    } else {
        "".to_string()
    };
    let use_alternate_path = if args.is_present("use_alternate_path") {
        "true".to_string()
    } else {
        "".to_string()
    };
    let set_working_directory = if args.is_present("set_working_directory") {
        "true".to_string()
    } else {
        "".to_string()
    };

    let runner_buf = patch_runner(
        &arch,
        &exec_name,
        &target_name,
        &uid,
        &use_temp_dir,
        &use_alternate_path,
        &set_working_directory,
    )?;

    create_tgz(&input_dirs, &main_tgz_path, compression)?;

    let exec_name = Path::new(args.value_of("output").unwrap());
    println!(
        "Creating self-contained application binary {:?}...",
        exec_name
    );
    create_app(&runner_buf, &input_tgzs, &exec_name)?;
    println!("All done");
    Ok(())
}

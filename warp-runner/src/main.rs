extern crate dirs;
#[macro_use]
extern crate log;
extern crate simple_logger;

use log::Level;
use std::env;
use std::error::Error;
use std::ffi::*;
use std::fs;
use std::io;
use std::path::*;
use std::process;

mod executor;
mod extractor;

static TARGET_FILE_NAME_BUF: &[u8] = b"tVQhhsFFlGGD3oWV4lEPST8I8FEPP54IM0q7daes4E1y3p2U2wlJRYmWmjPYfkhZ0PlT14Ls0j8fdDkoj33f2BlRJavLj3mWGibJsGt5uLAtrCDtvxikZ8UX2mQDCrgE\0";
static TARGET_UID_BUF: &[u8] = b"DR1PWsJsM6KxNbng9Y38\0";

fn build_uid() -> &'static str {
    read_magic("TARGET_UID_BUF", &TARGET_UID_BUF)
}

fn target_file_name() -> &'static str {
    read_magic("TARGET_FILE_NAME_BUF", &TARGET_FILE_NAME_BUF)
}

fn read_magic(magic_name: &str, magic: &'static [u8]) -> &'static str {
    let nul_pos = magic
        .iter()
        .position(|elem| *elem == b'\0')
        .expect(&format!("{} has no NUL terminator", magic_name));

    let slice = &magic[..(nul_pos + 1)];
    CStr::from_bytes_with_nul(slice)
        .expect(&format!("Can't convert {} slice to CStr", magic_name))
        .to_str()
        .expect(&format!("Can't convert {} CStr to str", magic_name))
}

#[cfg(not(feature = "runtime-path-alternative"))]
fn cache_path(file_name: &str, build_uid: &str) -> PathBuf {
    let cache_folder_name = {
        if !build_uid.is_empty() {
            format!("{}.{}", file_name, build_uid)
        } else {
            format!("{}", file_name)
        }
    };
    let mut dir = dirs::data_local_dir().expect("No data local dir found");
    #[cfg(all(feature = "runtime-path-windows-temp", target_family = "windows"))]
    {
        dir = dir.join("Temp");
    }
    dir = dir.join("warp").join("packages").join(cache_folder_name);
    dir
}
#[cfg(feature = "runtime-path-alternative")]
fn cache_path(file_name: &str, build_uid: &str) -> PathBuf {
    let mut dir = dirs::data_local_dir().expect("No data local dir found");
    #[cfg(all(feature = "runtime-path-windows-temp", target_family = "windows"))]
    {
        dir = dir.join("Temp");
    }
    dir = dir.join(file_name).join("app");
    if !build_uid.is_empty() {
        dir = dir.join(build_uid)
    }
    dir
}

fn extract(exe_path: &Path, cache_path: &Path) -> io::Result<()> {
    fs::remove_dir_all(cache_path).ok();
    extractor::extract_to(&exe_path, &cache_path)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("WARP_TRACE").is_ok() {
        simple_logger::init_with_level(Level::Trace)?;
    }

    let build_uid = build_uid();
    let self_path = env::current_exe()?;
    let self_file_name = self_path.file_name().unwrap().to_string_lossy();

    let cache_path = cache_path(&self_file_name, &build_uid);
    trace!("self_path={:?}", self_path);
    trace!("self_file_name={:?}", self_file_name);
    trace!("build_uid={:?}", build_uid);
    trace!("cache_path={:?}", cache_path);

    let target_file_name = target_file_name();
    let target_path = cache_path.join(target_file_name);

    trace!("target_exec={:?}", target_file_name);
    trace!("target_path={:?}", target_path);

    match fs::metadata(&cache_path) {
        Ok(cache) => {
            if cache.modified()? >= fs::metadata(&self_path)?.modified()? {
                trace!("cache is up-to-date");
            } else {
                trace!("cache is outdated");
                extract(&self_path, &cache_path)?;
            }
        }
        Err(_) => {
            trace!("cache not found");
            extract(&self_path, &cache_path)?;
        }
    }

    let exit_code = executor::execute(&target_path)?;
    process::exit(exit_code);
}

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

extern crate base64;
use base64::decode;

fn process_malware(filename: &std::path::Path) {
    // our "happy path" is the unhappy path where a user has executed a script
    // We are going to raise alarms by adding the EICAR string
    // Rename the original file preventing it from being run in future
    // https://stackoverflow.com/questions/43019846/best-way-to-format-a-file-name-based-on-another-path-in-rust
    let mut newname = PathBuf::from(filename);
    newname.set_file_name(format!(
        "DANGEROUS {}{}",
        newname.file_stem().unwrap().to_str().unwrap(),
        ".txt"
    ));
    if let Err(e) = fs::rename(filename, newname) {
        display_information(Some(&format!("Failed to rename file: {}", e)));
        return;
    };

    // Create a new file with the same name, .com extension to ensure EICAR traps it.
    // Why yes, the original version of this script did write EICAR to .js files and several AV vendors wouldn't flag it
    let mut eicarfile = PathBuf::from(filename);
    eicarfile.set_extension("com");
    let mut file = match File::create(eicarfile) {
        Ok(f) => f,
        Err(e) => {
            display_information(Some(&format!("Failed to create new file: {}", e)));
            return;
        }
    };
    // In order to avoid this application itself being flagged by endpoint software, we've encoded our string
    // The below is the EICAR test string, with a new line before and after
    let eicarb64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK";
    // The decode has to be safe as the B64 input is hard coded
    if let Err(e) = file.write_all(&decode(eicarb64).unwrap()) {
        display_information(Some(&format!("Failed to write EICAR to file: {}", e)));
        return;
    };

    display_information(None);
}

fn main() {
    println!("open_safety: https://lolware.net");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("This program should be called with a parameter");
        return;
    }

    let path = match Path::new(&args[1]).canonicalize() {
        Ok(buf) => buf,
        Err(x) => {
            println!("Error with provided file name: {}", x);
            return;
        }
    };

    if let Err(e) = check_safe_extension(&path) {
        display_information(Some(e));
        return;
    }
    if let Err(e) = check_safe_path(&path) {
        display_information(Some(e));
        return;
    }
    if !path.is_file() {
        display_information(Some("Filename provided is not a valid file"));
        return;
    }
    process_malware(&path);
}

fn check_safe_extension(path: &std::path::Path) -> Result<(), &str> {
    // To ensure this application doesn't clobber anything unwanted, we check the filename against an extension allow list
    let extension = match path.extension().and_then(OsStr::to_str) {
        Some(ext) => ext,
        None => {
            return Err("Filename provided did not have an extension");
        }
    };

    let allowed_extensions = ["js", "jse", "vbs", "wsf", "wsh", "hta"];
    if !allowed_extensions.contains(&extension) {
        return Err("Filename provided did not have an allowed extension");
    }
    Ok(())
}

fn check_safe_path(path: &std::path::Path) -> Result<(), &str> {
    // To ensure this application doesn't clobber anything unwanted, we check the path against a block list
    // This is a "best effort" type of test and obviously doesn't address all possible risks
    let canonical = path.to_str().expect("convert to path");
    if canonical.starts_with("\\\\?\\C:\\Windows\\")
        || canonical.starts_with("\\\\?\\C:\\Program Files")
    {
        return Err("File resides in unsafe path");
    }
    Ok(())
}

fn display_information(input: Option<&str>) {
    let display = r##"
    
    ================================================================

    This computer attempted to open a file type that is not usually
    associated with legitimate activities and has been protected by
    the open_safety system.

    If you are a developer or admin who is certain a script is safe,
    scripts can be run by passing as arguments to
    c:\windows\system32\cscript.exe

    This application will attempt to raise an alarm that should be
    seen by your IT security team.

    "##;

    let notice = match input {
        None => String::from("The potentially malicious application has been defanged. A substitute file was created to raise alarms"),
        Some(x) => format!("Unfortunately the following error was encountered when triaging this issue:\n    {}", x)
    };
    println!("{}{}", display, notice);
    pause();
}

fn pause() {
    // From: https://users.rust-lang.org/t/rusts-equivalent-of-cs-system-pause/4494/3
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0_u8]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::{check_safe_extension, check_safe_path, Path};
    #[test]
    fn rejects_bad_extensions() {
        assert!(check_safe_extension(Path::new("filename.bad")).is_err());
        assert!(check_safe_extension(Path::new("filename")).is_err());
    }
    #[test]
    fn accepts_good_extensions() {
        assert!(check_safe_extension(Path::new("filename.js")).is_ok());
        assert!(check_safe_extension(Path::new("C:\\test.folder\\filename.js")).is_ok());
    }
    #[test]
    fn rejects_bad_paths() {
        // This is a valid for the the safe path check, but due to the extension it should never be practically called
        // This isn't technically accurate as check_safe_path is always called after canonicalize(). However,
        // that function relies on the file existing which is a real mess for CI
        assert!(check_safe_path(Path::new("\\\\?\\C:\\Windows\\win.ini")).is_err());
    }
    #[test]
    fn accepts_good_paths() {
        // This path isn't valid for the rest of our application as it's a folder, but it's valid for this test.
        assert!(check_safe_path(Path::new("C:\\Users\\public\\")).is_ok());
    }
}

use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::path::Path;
use std::ffi::OsStr;

extern crate base64;
use base64::decode;

fn process_malware(filename: &std::path::Path) {
    // our "happy path" is the unhappy path where a user has executed a script
    // We are going to raise alarms by adding the EICAR string
    
    // Rename the original file preventing it from being run in future
    // https://stackoverflow.com/questions/43019846/best-way-to-format-a-file-name-based-on-another-path-in-rust
    let mut newname = PathBuf::from(filename);
    newname.set_file_name(format!("DANGEROUS {}{}", newname.file_stem().unwrap().to_str().unwrap(), ".txt"));
    fs::rename(filename, newname).expect("Failed to rename file");

    // Create a new file with the same name, .com extension to ensure EICAR traps it.
    // Why yes, the original version of this script did write EICAR to .js files and several AV vendors wouldn't flag it
    let mut eicarfile = PathBuf::from(filename);
    eicarfile.set_extension("com");
    let mut file = File::create(eicarfile).expect("cannot create file");
  
    // In order to avoid this application itself being flagged by endpoint software, we've encoded our string
    // The below is the EICAR test string, with a new line before and after
    let eicarb64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK";
    // The decode has to be safe as the B64 input is hard coded
    file.write_all(&decode(eicarb64).unwrap()).expect("Couldn't edit file");
}

fn main() {
    println!("Hello, world!");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("This program should be called with a parameter");
        return;
    }

    let path = match Path::new(&args[1]).canonicalize() {
        Ok(buf) => buf,
        Err(x) => {
            println!("This application should be called with a valid filename as a parameter: {}", x);
            return;
        }
    };

    if !check_safe_extension(&path) || !check_safe_path(&path) {
        return;
    }
    if !path.is_file() {
        println!("Not a file");
        return;
    }
    process_malware(&path)
}

fn check_safe_extension(path: &std::path::Path) -> bool {
    // To ensure this application doesn't clobber anything unwanted, we check the filename against an extension allow list
    let extension = match path.extension().and_then(OsStr::to_str) {
        Some(ext) => ext,
        None => {
            println!("Missing file extension");
            return false;
        }
    };

    let allowed_extensions = [ "js", "jse", "vbs"];
    println!("File extension is {}", extension);
    if !allowed_extensions.contains(&extension) {
        println!("Disallowed extension");
        return false;
    }
    true
}

fn check_safe_path(path: &std::path::Path) -> bool {
    // To ensure this application doesn't clobber anything unwanted, we check the path against a block list
    // This is a "best effort" type of test and obviously doesn't address all possible risks
    let canonical = path.to_str().expect("convert to path");
    println!("Canonical path is ;{};", canonical);
    if canonical.starts_with("\\\\?\\C:\\Windows\\") || canonical.starts_with("\\\\?\\C:\\Program Files") {
        println!("Unsafe path");
        return false;
    }
    true
}


#[cfg(test)]
#[test]
fn rejects_bad_extensions() {
    assert!(!check_safe_extension(Path::new("filename.bad")));
    assert!(!check_safe_extension(Path::new("filename")));
}
#[test]
fn accepts_good_extensions() {
    assert!(check_safe_extension(Path::new("filename.js")));
    assert!(check_safe_extension(Path::new("C:\\test.folder\\filename.js")));
}

/// [string]$Root = ".\AppControl Manager"
/// [string]$ExePath = "$Root\eXclude\ResourceValidator\target\x86_64-pc-windows-msvc\release\ResourceValidator-X64.exe"
/// . $ExePath $Root "$Root\Strings\en-US\Resources.resw" "$Root\Strings"
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context, Result, anyhow};
use quick_xml::Reader;
use quick_xml::events::Event;
use regex::Regex;

// Main function that orchestrates the entire process, returning a Result to handle errors
fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <cs_dir> <resx_file> <resources_root>", args[0]);
        exit(1);
    }

    let cs_dir: PathBuf = PathBuf::from(&args[1]);
    let resx_file: PathBuf = PathBuf::from(&args[2]);
    let resources_root: PathBuf = PathBuf::from(&args[3]);

    // === CONFIGURATION ===
    // These paths define where the code looks for C# files, the English resource file, and all resource files
    // cs_dir is the folder containing the .cs files.
    // resx_file is the main English .resx or .resw file.
    // resources_root is the root folder containing all resource-language folders (e.g., en-US, hebrew, etc.)
    // =====================

    // Step 1: Parse the English resource file
    // Parse the main English .resx or .resw file to extract keys, values, and detect duplicates
    // `parse_resx_data` returns a ResxInfo struct with all necessary data
    let resx_info = parse_resx_data(&resx_file)
        .with_context(|| format!("Failed to parse resx file {:?}", resx_file))?; // Add context for error reporting

    // Reporting basic statistics
    // Print the total number of <data> entries found in the resource file (including duplicates)
    println!(
        "Total strings in resource file: {}",
        resx_info.total_entries
    );

    // If there are duplicate keys (same key appearing multiple times), report them
    if !resx_info.duplicate_keys.is_empty() {
        println!("Duplicate keys found in resource file:");
        for key in &resx_info.duplicate_keys {
            let values = &resx_info.key_values[key];
            if values.iter().all(|v| v == &values[0]) {
                println!("  - '{}' (all values identical: '{}')", key, values[0]);
            } else {
                println!("  - '{}' (different values:)", key);
                for value in values {
                    println!("    - '{}'", value);
                }
            }
        }
    }

    // If there are keys with differing values, report and exit without deduplication
    if !resx_info.differing_values.is_empty() {
        println!("Keys with differing values found. Please handle manually. No deduplication performed.");
        exit(1);
    }

    // Only proceed with deduplication if there are no differing values
    if !resx_info.duplicate_values.is_empty() {
        println!("Duplicate values assigned to multiple no-dot keys:");

        for (value, keys) in &resx_info.duplicate_values {
            println!("  Value `{}` used by keys:", value); // Show the duplicated value
            for key in keys {
                println!("    - {}", key); // List all keys sharing this value
            }
        }

        // Step 2: Clean up duplicate values
        // Remove extra <data> entries from the English resource file and update C# code to use a single key
        process_value_duplicates(&resx_file, &resx_info.duplicate_values, &cs_dir)
            .with_context(|| "Failed to process and clean up duplicate values")?;
        println!("Duplicate-value cleanup complete.");
    }

    // Prepare for key validation
    // Create a set of all resource keys in lowercase for case-insensitive comparison
    let resx_keys_lower: HashSet<String> = resx_info
        .key_values
        .keys()
        .map(|k: &String| k.to_lowercase()) // Convert each key to lowercase
        .collect(); // Collect into a HashSet for efficient lookup

    // Step 3: Scan C# files for resource key usage
    // Look for `GlobalVars.Rizz.GetString("KEY")` calls in all .cs files to see which keys are used
    let used_keys: HashSet<String> = scan_cs_for_getstring(&cs_dir)
        .with_context(|| format!("Failed to scan C# files in {:?}", cs_dir))?;

    // Step 4: Validate used keys against the resource file
    // Check if all keys used in C# code exist in the resource file, accounting for '/' vs '.' and case
    let mut missing: Vec<String> = Vec::new(); // Collect keys that don't exist in the resource file
    for key in &used_keys {
        let key_lower: String = key.to_lowercase(); // Convert the used key to lowercase

        if !resx_keys_lower.contains(&key_lower) {
            // If not found, try normalizing by replacing '/' with '.' (common in resource naming)
            let normalized_lower: String = key.replace('/', ".").to_lowercase();
            if !resx_keys_lower.contains(&normalized_lower) {
                missing.push(key.clone()); // If still not found, it's missing
            }
        }
    }

    // If any keys are missing, report them and exit with an error code
    if !missing.is_empty() {
        eprintln!("Error: Found GlobalVars.Rizz.GetString keys not in resx:");
        for key in missing {
            eprintln!("  - {}", key); // List each missing key
        }
        exit(1);
    }

    println!("All GlobalVars.Rizz.GetString keys are valid.");

    // Prepare English key set for non-English validation
    // Create a set of exact English keys (case-sensitive) to compare against non-English resource files
    let english_keys: HashSet<String> = resx_info.key_values.keys().cloned().collect();

    // Step 5: Detect extra keys in non-English resource files
    // Identify keys in non-English files that don't exist in the English file
    let extra_report: Vec<(PathBuf, Vec<String>)> =
        detect_non_english_extra_keys(&english_keys, &resources_root)
            .with_context(|| "Failed to detect extra non-English resource keys")?;

    if extra_report.is_empty() {
        println!("No extra keys found in non-English resource files.");
    } else {
        println!("Extra keys found in non-English resource files (not in English):");

        for (file, keys) in &extra_report {
            println!("  File: {:?}", file); // Show the file path
            for k in keys {
                println!("    - {}", k); // List each extra key
            }
        }
    }

    // Step 5.5: Detect duplicate keys in non-English resource files ===
    let non_english_duplicate_report = detect_duplicate_keys_non_english(&resources_root)
        .with_context(|| "Failed to detect duplicate keys in non-English resource files")?;

    if non_english_duplicate_report.is_empty() {
        println!("No duplicate keys found in non-English resource files.");
    } else {
        println!("Duplicate keys in non-English resource files:");
        for (file, keys) in non_english_duplicate_report {
            println!("  File: {:?}", file);
            for key in keys {
                println!("    - {}", key);
            }
        }
    }
    // ====================================================================

    // Step 6: Prune non-English resource files
    // Remove <data> entries from non-English files if their keys aren't in the English file
    let prune_report: Vec<(PathBuf, Vec<String>)> =
        prune_non_english_items(&english_keys, &resources_root)
            .with_context(|| "Failed to prune non-English resource files")?;

    if prune_report.is_empty() {
        println!("No entries were pruned from non-English resource files.");
    } else {
        println!("Pruned entries from non-English resource files:");
        for (file, keys) in prune_report {
            println!("  File: {:?}", file); // Show the file path
            for k in keys {
                println!("    - {}", k); // List each pruned key
            }
        }
    }

    // Step 7: Normalize empty lines in code files
    // Ensure no more than two consecutive empty lines in .cs and .xaml files
    let normalize_report: Vec<PathBuf> = normalize_empty_lines(&cs_dir)
        .with_context(|| "Failed to normalize empty lines in code files")?;

    if normalize_report.is_empty() {
        println!("No files needed empty-line normalization.");
    } else {
        println!("Normalized empty lines in files:");
        for file in normalize_report {
            println!("  {:?}", file); // List each modified file
        }
    }

    // Step 8: Validate x:Uid usage in XAML files
    // Check that properties used with x:Uid in XAML match allowed properties for each element type
    let xuid_report: XuidValidateReport = validate_xuid_usage(&resx_info.key_values, &cs_dir)
        .with_context(|| "Failed to validate x:Uid usage in XAML files")?;

    if xuid_report.element_types.is_empty() {
        println!("No x:Uid usages found in XAML files.");
    } else {
        println!("XAML elements using x:Uid:");
        for elem in &xuid_report.element_types {
            println!("  - {}", elem); // List element types using x:Uid
        }
    }
    if !xuid_report.unknown_elements.is_empty() {
        println!("Unknown element types encountered (need logic):");
        for elem in &xuid_report.unknown_elements {
            println!("  - {}", elem); // List unknown elements
        }
    }
    if !xuid_report.mismatches.is_empty() {
        println!("Invalid x:Uid property usages detected:");
        for (file, element, uid, invalid_props) in &xuid_report.mismatches {
            println!(
                "  File: {:?}, Element: {}, x:Uid=\"{}\"",
                file, element, uid
            );
            println!("    Invalid properties:");
            for prop in invalid_props {
                println!("      - {}", prop); // List invalid properties
            }
        }
    }

    Ok(()) // Return Ok if everything succeeds
}

/// Detect duplicate keys in non-English resource files
fn detect_duplicate_keys_non_english(
    root: &PathBuf,
) -> Result<Vec<(PathBuf, Vec<String>)>> {
    let mut report: Vec<(PathBuf, Vec<String>)> = Vec::new();
    visit_non_english_for_duplicates(root, &mut report)?;
    Ok(report)
}

fn visit_non_english_for_duplicates(
    dir: &Path,
    report: &mut Vec<(PathBuf, Vec<String>)>,
) -> Result<()> {
    // Regex to match <data> blocks and capture the key
    let data_re: Regex =
        Regex::new(r#"(?s)<data[^>]*name\s*=\s*"(?P<key>[^"]+)"[^>]*>.*?</data>\s*"#)
            .expect("Failed to compile data-block regex");

    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();

        // Skip the English folder (en-US) as we're only checking non-English files
        if entry.file_name().to_string_lossy() == "en-US" {
            continue;
        }

        if path.is_dir() {
            visit_non_english_for_duplicates(&path, report)?; // Recurse into subdirectories
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) {

                // Process .resx or .resw files
                if ext.eq_ignore_ascii_case("resx") || ext.eq_ignore_ascii_case("resw") {
                    let text: String = fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {:?}", path))?;
                    let mut key_counts: HashMap<String, usize> = HashMap::new();

                    // Check each <data> block's key
                    for cap in data_re.captures_iter(&text) {
                        if let Some(m) = cap.name("key") {
                            let key: String = m.as_str().to_string();
                            *key_counts.entry(key).or_insert(0) += 1;
                        }
                    }
                    // Report keys that appear more than once
                    let duplicates: Vec<String> = key_counts
                        .into_iter()
                        .filter_map(|(k, c)| if c > 1 { Some(k) } else { None })
                        .collect();
                    if !duplicates.is_empty() {
                        report.push((path.to_path_buf(), duplicates));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Processes duplicate values in the English resource file by removing extra entries
/// and updating C# code to reference a single key for each duplicate value group
fn process_value_duplicates(
    resx_file: &PathBuf, // Path to the English resource file
    duplicate_values: &Vec<(String, Vec<String>)>, // Groups of (value, [keys]) with duplicates
    cs_dir: &PathBuf,    // Directory containing C# files
) -> Result<()> {
    let resx_text: String = fs::read_to_string(resx_file)
        .with_context(|| format!("Cannot read resx file {:?}", resx_file))?;

    let data_re = Regex::new(r#"(?s)<data\b[^>]*\bname\s*=\s*"([^"]+)"[^>]*>.*?</data>\s*"#)
        .expect("Failed to compile data-block regex");

    // Determine which keys to keep and which to remove
    let mut keep_keys: HashSet<String> = HashSet::new();
    let mut remove_keys: HashMap<String, String> = HashMap::new(); // Maps removed key to kept key

    for (_value, keys) in duplicate_values {
        if keys.len() < 2 {
            continue;
        }
        let keep_key = keys[0].clone(); // Keep the first key as requested
        keep_keys.insert(keep_key.clone());
        for remove_key in &keys[1..] {
            remove_keys.insert(remove_key.clone(), keep_key.clone());
        }
    }

    // Rewrite the resx file, keeping only the first occurrence of each key
    let mut output = String::with_capacity(resx_text.len());
    let mut last_idx = 0;
    let mut seen: HashSet<String> = HashSet::new();

    for m in data_re.captures_iter(&resx_text) {
        let full = m.get(0).unwrap();
        let key = m.get(1).unwrap().as_str();

        // Write everything before this block
        output.push_str(&resx_text[last_idx..full.start()]);

        if !seen.contains(key) && (!remove_keys.contains_key(key) || keep_keys.contains(key)) {
            output.push_str(full.as_str());
            seen.insert(key.to_string());
        }
        // Skip if it's a key to remove (unless it's the kept key)

        last_idx = full.end();
    }
    // Write the rest of the file after the last matched block
    output.push_str(&resx_text[last_idx..]);

    // Write the modified resource file back to disk
    fs::write(resx_file, output)
        .with_context(|| format!("Failed to write updated resx file {:?}", resx_file))?;

    // Update C# references for each group of duplicate keys
    for (_value, keys) in duplicate_values {
        if keys.len() < 2 {
            continue;
        }
        let keep_key = &keys[0]; // First key is kept
        let remove_keys = &keys[1..]; // Rest are removed
        update_cs_references(cs_dir, keep_key, remove_keys)
            .with_context(|| format!("Failed to update C# references for key `{}`", keep_key))?;
    }

    Ok(())
}

/// Updates all .cs files under a directory by replacing GetString calls for old keys with a new key
fn update_cs_references(
    dir: &PathBuf,       // Directory to search for .cs files
    new_key: &str,       // The key to use in replacements
    old_keys: &[String], // List of keys to replace
) -> Result<()> {
    // Recursively iterate over all entries in the directory
    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read directory {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();
        if path.is_dir() {
            // If it's a directory, recurse into it
            update_cs_references(&path, new_key, old_keys)?;
        } else if path.is_file()
            && path
                .extension()
                .map_or(false, |e: &std::ffi::OsStr| e == "cs")
        {
            // Process only .cs files
            let mut content: String = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read file {:?}", path))?;
            let original: String = content.clone(); // Keep original for comparison

            // Replace each old key's GetString call with the new key
            for old in old_keys {
                // Match `GlobalVars.Rizz.GetString("old_key")` with optional whitespace
                let call_pattern: String = format!(
                    r#"GlobalVars\.Rizz\.GetString\s*\(\s*"{}"\s*\)"#,
                    regex::escape(old)
                );
                let call_re: Regex = Regex::new(&call_pattern)
                    .with_context(|| format!("Invalid regex for updating key `{}`", old))?;
                let replacement: String = format!(r#"GlobalVars.Rizz.GetString("{}")"#, new_key);
                content = call_re
                    .replace_all(&content, replacement.as_str())
                    .to_string();
            }

            // If the content changed, write it back
            if content != original {
                fs::write(&path, content)
                    .with_context(|| format!("Failed to write updated file {:?}", path))?;
            }
        }
    }
    Ok(())
}

/// Parses a .resx or .resw file to extract keys and values, and detect duplicates
fn parse_resx_data(path: &PathBuf) -> Result<ResxInfo> {
    // Open the file and set up an XML reader with buffering for efficiency
    let file: File =
        File::open(path).with_context(|| format!("Cannot open resx file {:?}", path))?;

    let mut reader: Reader<BufReader<File>> = Reader::from_reader(BufReader::new(file));

    reader.config_mut().trim_text(true); // Trim whitespace in text nodes

    let mut buf: Vec<u8> = Vec::new(); // Buffer for XML events
    let mut key_values: HashMap<String, Vec<String>> = HashMap::new(); // Stores key-value pairs
    let mut key_counts: HashMap<String, usize> = HashMap::new(); // Tracks key occurrences
    let mut total_entries = 0; // Counts total <data> elements

    // Parse the XML file event by event
    loop {
        buf.clear(); // Clear buffer for each event
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == b"data" => {
                total_entries += 1; // Increment entry count

                // Extract the `name` attribute from the <data> element
                let mut current_key: Option<String> = None;
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == b"name" {
                        let raw = attr
                            .unescape_value()
                            .map_err(|e| anyhow!("XML unescape error: {}", e))?;
                        current_key = Some(raw.trim().to_string());
                        break;
                    }
                }
                let key: String = match current_key {
                    Some(k) => k,
                    None => continue, // Skip if no name attribute
                };

                // Extract the text inside the <value> element
                let mut value_text: String = String::new();
                loop {
                    buf.clear();
                    match reader.read_event_into(&mut buf) {
                        Ok(Event::Start(e2)) if e2.name().as_ref() == b"value" => {
                            buf.clear();
                            if let Ok(Event::Text(txt)) = reader.read_event_into(&mut buf) {
                                value_text = txt
                                    .unescape()
                                    .map_err(|e: quick_xml::Error| {
                                        anyhow!("XML unescape error: {}", e)
                                    })?
                                    .to_string();
                            }
                        }
                        Ok(Event::End(e2)) if e2.name().as_ref() == b"data" => break, // End of <data>
                        Ok(Event::Eof) => break, // Unexpected end of file
                        _ => {}
                    }
                }

                // Add to key_values
                key_values.entry(key.clone()).or_default().push(value_text.clone());

                // Track key occurrences for duplicate detection
                let cnt: &mut usize = key_counts.entry(key.clone()).or_insert(0);
                *cnt += 1;
            }
            Ok(Event::Eof) => break, // End of file reached
            Ok(_) => {}              // Ignore other events
            Err(e) => {
                return Err(anyhow!(
                    "Error parsing XML at position {}: {}",
                    reader.buffer_position(),
                    e
                ));
            }
        }
    }

    // Identify keys that appear more than once
    let duplicate_keys: Vec<String> = key_counts
        .into_iter()
        .filter_map(|(k, c)| if c > 1 { Some(k) } else { None })
        .collect();

    // Identify values used by multiple top-level keys (no dots in key name)
    let mut value_map: HashMap<String, Vec<String>> = HashMap::new();
    for (key, values) in &key_values {
        if let Some(first_value) = values.first() {
            value_map.entry(first_value.clone()).or_default().push(key.clone());
        }
    }
    let duplicate_values: Vec<(String, Vec<String>)> = value_map
        .into_iter()
        .filter_map(|(value, keys)| {
            let no_dot: Vec<String> = keys.into_iter().filter(|k| !k.contains('.')).collect();
            if no_dot.len() > 1 {
                Some((value, no_dot)) // Return value and its keys if more than one
            } else {
                None
            }
        })
        .collect();

    let differing_values: Vec<String> = key_values
        .iter()
        .filter_map(|(key, values)| {
            if values.len() > 1 && !values.iter().all(|v| v == &values[0]) {
                Some(key.clone())
            } else {
                None
            }
        })
        .collect();

    // Return the parsed data and statistics
    Ok(ResxInfo {
        key_values,
        total_entries,
        duplicate_keys,
        duplicate_values,
        differing_values,
    })
}

/// Scans all .cs files under a directory for `GlobalVars.Rizz.GetString("KEY")` calls
fn scan_cs_for_getstring(root: &PathBuf) -> Result<HashSet<String>> {
    // Regex to match GetString calls and capture the key
    let pattern = Regex::new(r#"GlobalVars\.Rizz\.GetString\s*\(\s*"(?P<key>[^"]+)"\s*\)"#)
        .expect("Failed to compile regex"); // Panic if regex is invalid (shouldn't happen)

    let mut keys = HashSet::new(); // Collect unique keys

    visit_dir(root, &pattern, &mut keys)?; // Recursively scan files

    Ok(keys)
}

/// Helper function to recursively visit directories and scan .cs files for GetString keys
fn visit_dir(dir: &Path, pattern: &Regex, keys: &mut HashSet<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read directory {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();
        if path.is_dir() {
            visit_dir(&path, pattern, keys)?; // Recurse into subdirectories
        } else if path.is_file() && path.extension().map_or(false, |e| e == "cs") {
            // Read the .cs file
            let mut content: String = String::new();

            File::open(&path)
                .with_context(|| format!("Failed to open {:?}", path))?
                .read_to_string(&mut content)
                .with_context(|| format!("Failed to read {:?}", path))?;

            // Find all matches and add keys to the set
            for cap in pattern.captures_iter(&content) {
                if let Some(m) = cap.name("key") {
                    keys.insert(m.as_str().to_string());
                }
            }
        }
    }
    Ok(())
}

/// Detects keys in non-English resource files that don't exist in the English resource file
fn detect_non_english_extra_keys(
    en_keys: &HashSet<String>, // Set of English resource keys
    root: &PathBuf,            // Root directory of resource files
) -> Result<Vec<(PathBuf, Vec<String>)>> {
    let mut extras: Vec<(PathBuf, Vec<String>)> = Vec::new(); // Collect (file, [extra keys]) pairs
    visit_resources_extras(root, en_keys, &mut extras)?;
    Ok(extras)
}

/// Helper function to recursively visit resource directories and detect extra keys
fn visit_resources_extras(
    dir: &Path,
    en_keys: &HashSet<String>,
    extras: &mut Vec<(PathBuf, Vec<String>)>,
) -> Result<()> {
    // Regex to match <data> blocks and capture the key
    let data_re: Regex =
        Regex::new(r#"(?s)<data[^>]*name\s*=\s*"(?P<key>[^"]+)"[^>]*>.*?</data>\s*"#)
            .expect("Failed to compile data-block regex");

    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();

        // Skip the English folder (en-US) as we're only checking non-English files
        if entry.file_name().to_string_lossy() == "en-US" {
            continue;
        }

        if path.is_dir() {
            visit_resources_extras(&path, en_keys, extras)?; // Recurse into subdirectories
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) {
                // Process .resx or .resw files
                if ext.eq_ignore_ascii_case("resx") || ext.eq_ignore_ascii_case("resw") {
                    let text: String = fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {:?}", path))?;
                    let mut file_extras = Vec::new();
                    // Check each <data> block's key
                    for cap in data_re.captures_iter(&text) {
                        if let Some(m) = cap.name("key") {
                            let key: String = m.as_str().to_string();
                            if !en_keys.contains(&key) {
                                file_extras.push(key); // Add if not in English keys
                            }
                        }
                    }
                    if !file_extras.is_empty() {
                        extras.push((path.to_path_buf(), file_extras));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Prunes non-English resource files by removing entries with keys not in the English file
fn prune_non_english_items(
    en_keys: &HashSet<String>,
    root: &PathBuf,
) -> Result<Vec<(PathBuf, Vec<String>)>> {
    let mut report: Vec<(PathBuf, Vec<String>)> = Vec::new(); // Collect (file, [removed keys]) pairs
    visit_resources(root, en_keys, &mut report)?;
    Ok(report)
}

/// Helper function to recursively visit and prune non-English resource files
fn visit_resources(
    dir: &Path,
    en_keys: &HashSet<String>,
    report: &mut Vec<(PathBuf, Vec<String>)>,
) -> Result<()> {
    // Regex to match <data> blocks and capture the key
    let data_re: Regex =
        Regex::new(r#"(?s)<data[^>]*name\s*=\s*"(?P<key>[^"]+)"[^>]*>.*?</data>\s*"#)
            .expect("Failed to compile data-block regex");

    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();

        // Skip the English folder
        if entry.file_name().to_string_lossy() == "en-US" {
            continue;
        }

        if path.is_dir() {
            visit_resources(&path, en_keys, report)?; // Recurse into subdirectories
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) {
                if ext.eq_ignore_ascii_case("resx") || ext.eq_ignore_ascii_case("resw") {
                    let mut text = fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {:?}", path))?;
                    let mut removed_keys: Vec<String> = Vec::new();

                    // Identify keys to remove
                    for cap in data_re.captures_iter(&text) {
                        if let Some(m) = cap.name("key") {
                            let key: String = m.as_str().to_string();
                            if !en_keys.contains(&key) {
                                removed_keys.push(key);
                            }
                        }
                    }

                    // Remove each unwanted <data> block
                    for key in &removed_keys {
                        let pattern: String = format!(
                            r#"(?s)<data[^>]*name\s*=\s*"{}"[^>]*>.*?</data>\s*"#,
                            regex::escape(key)
                        );
                        let re: Regex = Regex::new(&pattern)
                            .with_context(|| format!("Invalid regex for pruning key `{}`", key))?;
                        text = re.replace_all(&text, "").to_string();
                    }

                    // If anything was removed, update the file and report it
                    if !removed_keys.is_empty() {
                        fs::write(&path, &text)
                            .with_context(|| format!("Failed to write {:?}", path))?;
                        report.push((path.to_path_buf(), removed_keys));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Normalizes empty lines in .cs and .xaml files to a maximum of two consecutive empty lines
fn normalize_empty_lines(root: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut modified: Vec<PathBuf> = Vec::new(); // List of files that were changed

    // Regex to match more than two consecutive empty lines
    let empty_line_re: Regex = Regex::new(r"(?m)^\s*$\r?\n(\s*\r?\n){2,}")?;

    visit_and_normalize(root, &empty_line_re, &mut modified)?;

    Ok(modified)
}

/// Helper function to recursively visit and normalize empty lines in files
fn visit_and_normalize(dir: &PathBuf, re: &Regex, modified: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read directory {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();
        if path.is_dir() {
            visit_and_normalize(&path, re, modified)?; // Recurse into subdirectories
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) {
                if ext.eq_ignore_ascii_case("cs") || ext.eq_ignore_ascii_case("xaml") {
                    let content = fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {:?}", path))?;

                    // Replace excessive empty lines with two newlines
                    let new: std::borrow::Cow<'_, str> = re.replace_all(&content, "\n\n");

                    if new != content {
                        fs::write(&path, new.as_ref())
                            .with_context(|| format!("Failed to write {:?}", path))?;
                        modified.push(path);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Struct to hold parsed data from a resource file
struct ResxInfo {
    /// Map of resource keys to their values
    key_values: HashMap<String, Vec<String>>,

    /// Total number of <data> entries, including duplicates
    total_entries: usize,

    /// List of keys that appear more than once
    duplicate_keys: Vec<String>,

    /// List of (value, [keys]) where the value is used by multiple top-level keys
    duplicate_values: Vec<(String, Vec<String>)>,

    /// List of keys with differing values
    differing_values: Vec<String>,
}

/// Struct to hold results of x:Uid validation in XAML files
struct XuidValidateReport {
    /// Set of element types that use x:Uid
    element_types: HashSet<String>,

    /// Set of unrecognized element types
    unknown_elements: HashSet<String>,

    /// List of (file, element, uid, [invalid properties]) for mismatches
    mismatches: Vec<(PathBuf, String, String, Vec<String>)>,
}

/// Validates that x:Uid usage in XAML files uses allowed properties for each element type
fn validate_xuid_usage(
    key_values: &HashMap<String, Vec<String>>, // English resource keys and values
    root: &PathBuf,                       // Directory containing XAML files
) -> Result<XuidValidateReport> {
    let mut report: XuidValidateReport = XuidValidateReport {
        element_types: HashSet::new(),
        unknown_elements: HashSet::new(),
        mismatches: Vec::new(),
    };

    // Defining allowed properties for each element type that can use x:Uid
    // So we can catch any possible errors early.
    let mut allowed: HashMap<&str, Vec<&str>> = HashMap::new();
    allowed.insert(
        "SettingsExpander",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Description",
            "Header",
        ],
    );
    allowed.insert(
        "Button",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "AnimatedCancellableButton",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "ToggleButton",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "AutoSuggestBox",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "PlaceholderText",
            "Header",
        ],
    );
    allowed.insert(
        "TextBlock",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Text",
        ],
    );
    allowed.insert(
        "SegmentedItem",
        vec![
            "Content"
        ],
    );
    allowed.insert(
        "MenuFlyoutSubItem",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Text",
        ],
    );
    allowed.insert(
        "ToggleMenuFlyoutItem",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Text",
        ],
    );
    allowed.insert(
        "ComboBox",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Header",
            "PlaceholderText",
        ],
    );
    allowed.insert(
        "NavigationViewItemHeader",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "ToggleSwitch",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "OffContent",
            "OnContent",
        ],
    );
    allowed.insert(
        "HyperlinkButton",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "InfoBar",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Title",
            "Message",
        ],
    );
    allowed.insert(
        "SettingsCard",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Header",
            "Description",
        ],
    );
    allowed.insert(
        "TextBox",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Header",
            "PlaceholderText",
            "Text",
        ],
    );
    allowed.insert(
        "NumberBox",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Header",
        ],
    );
    allowed.insert(
        "PasswordBox",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "PlaceholderText",
        ],
    );
    allowed.insert(
        "AppBarButton",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Label",
        ],
    );
    allowed.insert("Run", vec!["Text"]);
    allowed.insert(
        "NavigationViewItem",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "MenuFlyoutItem",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Text",
        ],
    );
    allowed.insert(
        "ContentDialog",
        vec![
            "AutomationProperties.HelpText",
            "CloseButtonText",
            "Title",
            "Text",
            "PrimaryButtonText",
        ],
    );
    allowed.insert(
        "DropDownButton",
        vec![
            "AutomationProperties.HelpText",
            "ToolTipService.ToolTip",
            "Content",
        ],
    );
    allowed.insert(
        "ComboBoxItem",
        vec![
            "Content"
        ],
    );
    allowed.insert(
        "RadioButton",
        vec![
            "Content"
        ],
    );
    allowed.insert(
        "RadioButtons",
        vec![
            "Header"
        ],
    );
    allowed.insert(
        "TabViewItem",
        vec![
            "Header"
        ],
    );

    // Regex to find elements with an x:Uid attribute
    let re: Regex = Regex::new(r#"<([A-Za-z0-9_:]+)\b[^>]*\bx:Uid\s*=\s*"([^"]+)""#)
        .expect("Failed to compile x:Uid regex");

    // Recursively validate XAML files
    visit_xaml(root, &re, key_values, &mut report, &allowed)?;

    Ok(report)
}

/// Helper function to recursively visit XAML files and validate x:Uid usage
fn visit_xaml(
    dir: &PathBuf,
    re: &Regex,
    key_values: &HashMap<String, Vec<String>>,
    report: &mut XuidValidateReport,
    allowed: &HashMap<&str, Vec<&str>>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Cannot read directory {:?}", dir))? {
        let entry: fs::DirEntry =
            entry.with_context(|| format!("Failed to read entry in {:?}", dir))?;
        let path: PathBuf = entry.path();

        if path.is_dir() {
            visit_xaml(&path, re, key_values, report, allowed)?; // Recurse into subdirectories
        } else if path.is_file()
            && path
                .extension()
                .map_or(false, |e| e.eq_ignore_ascii_case("xaml"))
        {
            let text: String = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read XAML {:?}", path))?;

            // Find all elements with x:Uid
            for cap in re.captures_iter(&text) {
                let raw_elem = &cap[1]; // Full element name (e.g., "Button" or "ns:Button")

                let uid = &cap[2]; // Value of x:Uid

                // Extract the base element name, removing namespace prefix if present
                let elem_name: &str = raw_elem.split(':').last().unwrap_or(raw_elem);

                // Handle versioned elements (e.g., ButtonV2) by stripping version suffix
                let base_elem: String =
                    if let Some(vcap) = Regex::new(r"^(.+?)V\d+$").unwrap().captures(elem_name) {
                        vcap[1].to_string()
                    } else {
                        elem_name.to_string()
                    };
                report.element_types.insert(base_elem.clone());

                // Get the allowed properties for this element, or mark as unknown
                let allowed_props: &Vec<&str> = if let Some(props) = allowed.get(base_elem.as_str())
                {
                    props
                } else {
                    report.unknown_elements.insert(base_elem.clone());
                    continue;
                };

                // Find all resource keys that start with "uid."
                let prefix: String = format!("{}.", uid);

                let mut actual_suffixes: Vec<String> = Vec::new();

                for key in key_values.keys() {
                    if key.starts_with(&prefix) {
                        actual_suffixes.push(key[prefix.len()..].to_string()); // Extract property suffix
                    }
                }

                // Check for invalid properties
                let mut invalid: Vec<String> = Vec::new();
                for suf in &actual_suffixes {
                    if !allowed_props.iter().any(|p: &&str| p == suf) {
                        invalid.push(suf.clone());
                    }
                }
                if !invalid.is_empty() {
                    report.mismatches.push((
                        path.clone(),
                        base_elem.clone(),
                        uid.to_string(),
                        invalid,
                    ));
                }
            }
        }
    }
    Ok(())
}
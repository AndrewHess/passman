use crate::aes;
use crate::utils;
use rand;
use rand::{RngCore, SeedableRng};
use sha3::{Digest, Sha3_256};
use std::{fmt, fs};

#[derive(Debug, std::cmp::PartialEq)]
pub struct Database {
    encryption_key: aes::MainKey,
    main_passkey_encrypted: String,
    password_verifying_hash: [u8; 32],
    password_verifying_hash_salt: [u8; 16],
    intermediate_passkey_salt: [u8; 16],
    entries: Vec<v1::Entry>,
}

impl Database {
    pub fn new(password: &str) -> Database {
        // Randomize the main encryption key and the salts.
        let encryption_key: aes::MainKey = utils::secure_random_bytes!(32);
        let password_verifying_hash_salt: [u8; 16] = utils::random_array!(u8, 16);
        let intermediate_passkey_salt: [u8; 16] = utils::random_array!(u8, 16);

        // Encrypt the main encryption key.
        let intermediate_encryption_key: aes::MainKey =
            salt_and_hash(password.as_bytes(), &intermediate_passkey_salt);
        let main_passkey_encrypted =
            utils::bytes_to_hex(&aes::encrypt(&encryption_key, &intermediate_encryption_key)[..]);

        // Create the salted hash used to verify password correctness on future logins.
        let password_verifying_hash =
            salt_and_hash(password.as_bytes(), &password_verifying_hash_salt);

        // Start with no entries.
        let entries = Vec::<v1::Entry>::new();

        Database {
            encryption_key: encryption_key,
            main_passkey_encrypted: main_passkey_encrypted,
            password_verifying_hash: password_verifying_hash,
            password_verifying_hash_salt: password_verifying_hash_salt,
            intermediate_passkey_salt: intermediate_passkey_salt,
            entries: entries,
        }
    }

    pub fn add(&mut self, username: &str, password: &str, website: &str, notes: &str) {
        self.entries.push(v1::Entry {
            id: self.next_available_id(),
            username: username.to_string(),
            password_raw: password.to_string(),
            website: website.to_string(),
            notes: notes.to_string(),
        });
    }

    pub fn remove(&mut self, id: usize) -> Result<(), String> {
        let i = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.id == id)
            .map(|(i, _)| i)
            .next()
            .ok_or_else(|| format!("Invalid ID: {}", id))?;

        // Remove the entry. Using `swap_remove()` is O(1) time but doesn't maintain
        // sorting--the last element is moved to index `i`. But we don't need the
        // vector to be sorted, so this is ok.
        self.entries.swap_remove(i);
        Ok(())
    }

    pub fn get_entry_long_form(&self, id: usize) -> Result<String, String> {
        Ok(self.get_entry(id)?.long_form())
    }

    // Search the database for entries which have `s` as an exact substring of their
    // username, website, or notes. Sort all of these entries by their ID (lower ID
    // appearing sooner), and return a string where each line is the `short_form()`
    // string for the corresponding entry.
    pub fn find(&self, s: &str) -> String {
        let mut matching_entries = self
            .entries
            .iter()
            .filter(|e| e.username.contains(s) || e.website.contains(s) || e.notes.contains(s))
            .collect::<Vec<&v1::Entry>>();

        matching_entries.sort_by(|&e1, &e2| e1.id.cmp(&e2.id));

        matching_entries
            .iter()
            .map(|e| e.short_form())
            .collect::<Vec<String>>()
            .join("\n")
    }

    pub fn set_entry_username(&mut self, id: usize, new_username: &str) -> Result<(), String> {
        self.get_entry_mut(id)?.username = new_username.to_string();
        Ok(())
    }

    pub fn set_entry_password(&mut self, id: usize, new_password: &str) -> Result<(), String> {
        self.get_entry_mut(id)?.password_raw = new_password.to_string();
        Ok(())
    }

    pub fn set_entry_website(&mut self, id: usize, new_website: &str) -> Result<(), String> {
        self.get_entry_mut(id)?.website = new_website.to_string();
        Ok(())
    }

    pub fn set_entry_notes(&mut self, id: usize, new_notes: &str) -> Result<(), String> {
        self.get_entry_mut(id)?.notes = new_notes.to_string();
        Ok(())
    }

    pub fn write(&self, filename: &str) -> Result<(), String> {
        fs::write(
            filename,
            self.to_str()
                .map_err(|_| "Failed to convert database to text")?,
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn read(filename: &str, password: &str) -> Result<Database, String> {
        if !std::path::Path::new(filename).exists() {
            return Err(format!("File {} does not exist", filename));
        }

        let contents = fs::read_to_string(filename)
            .map_err(|_| format!("Failed to read the file {}", filename))?;

        Self::from_str(&contents, password)
    }

    fn to_str(&self) -> Result<String, ()> {
        let mut s = format!("{}\n", FileFormatVersion::V1);
        s.push_str(
            &serde_json::to_string(&v1::EncryptedDatabase::from_database(&self)).map_err(|_| ())?,
        );
        Ok(s)
    }

    fn from_str(s: &str, password: &str) -> Result<Self, String> {
        let version = s.lines().next().ok_or("Missing version".to_string())?;
        let contents: &str = s
            .lines()
            .skip(1)
            .next()
            .ok_or("Nothing found after the database version".to_string())?;

        match version.parse::<FileFormatVersion>() {
            Ok(FileFormatVersion::V1) => v1::database_from_str(contents, password),
            Err(_) => Err(format!("Unknown database version: {}", version)),
        }
    }

    fn next_available_id(&self) -> usize {
        // If an entry is deleted, it's ID can be reused. If each id in
        // 1..=self.entries.len() is used, then the id self.entries.len() + 1
        // is guaranteed to be available because each entry has only one id.
        //
        // Note that ids are 1-indexed becuase they'll be shown to the user.
        let mut id_in_use = vec![false; self.entries.len()];
        self.entries.iter().for_each(|e| {
            if e.id <= id_in_use.len() {
                id_in_use[e.id - 1] = true
            }
        });
        1 + id_in_use
            .into_iter()
            .enumerate()
            .filter(|(_, in_use)| !in_use)
            .map(|(i, _)| i)
            .next()
            .unwrap_or_else(|| self.entries.len())
    }

    fn get_entry(&self, id: usize) -> Result<&v1::Entry, String> {
        Ok(self
            .entries
            .iter()
            .filter(|entry| entry.id == id)
            .next()
            .ok_or_else(|| format!("Invalid ID: {}", id))?)
    }

    fn get_entry_mut(&mut self, id: usize) -> Result<&mut v1::Entry, String> {
        Ok(self
            .entries
            .iter_mut()
            .filter(|entry| entry.id == id)
            .next()
            .ok_or_else(|| format!("Invalid ID: {}", id))?)
    }
}

fn salt_and_hash(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([password, salt].concat());

    let hash = hasher.finalize();
    assert_eq!(hash.len(), 32);

    hash[..32].try_into().unwrap()
}

pub enum FileFormatVersion {
    V1,
}

impl fmt::Display for FileFormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FileFormatVersion::V1 => write!(f, "{}", "v1.0"),
        }
    }
}

impl std::str::FromStr for FileFormatVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v1.0" => Ok(FileFormatVersion::V1),
            _ => Err(()),
        }
    }
}

mod v1 {
    use super::{salt_and_hash, Database};
    use crate::{aes, utils};
    use indoc;
    use serde;

    #[derive(Debug, std::cmp::PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Entry {
        pub id: usize,
        pub username: String,
        pub password_raw: String,
        pub website: String,
        pub notes: String,
    }

    impl Entry {
        pub fn short_form(&self) -> String {
            format!(
                "{:3}. {} {} {}",
                self.id,
                utils::pad_or_ellipsis!(self.username, 20),
                utils::pad_or_ellipsis!(self.website, 30),
                utils::pad_or_ellipsis!(self.notes, 20)
            )
        }

        pub fn long_form(&self) -> String {
            format!(
                indoc::indoc! {"
                Username: {}
                Password: {}
                Website: {}
                Notes: {}
                "},
                self.username, self.password_raw, self.website, self.notes
            )
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct EncryptedDatabase {
        // Each field is a string of hex.
        pub main_passkey_encrypted: String,
        pub password_verifying_hash: String,
        pub password_verifying_hash_salt: String,
        pub intermediate_passkey_salt: String,
        pub entries: String, // The credentials as JSON and then encrypted.
    }

    impl EncryptedDatabase {
        pub fn from_database(database: &Database) -> Self {
            let entries_json_bytes = match serde_json::to_vec(&database.entries) {
                Ok(x) => x,
                Err(_) => panic!("Failed to encrypt data"),
            };

            let encrypted_entries = aes::encrypt(&entries_json_bytes, &database.encryption_key)
                .iter()
                .map(|b: &u8| format!("{:02x}", *b))
                .collect();

            EncryptedDatabase {
                main_passkey_encrypted: database.main_passkey_encrypted.clone(),
                password_verifying_hash: utils::bytes_to_hex(&database.password_verifying_hash),
                password_verifying_hash_salt: utils::bytes_to_hex(
                    &database.password_verifying_hash_salt,
                ),
                intermediate_passkey_salt: utils::bytes_to_hex(&database.intermediate_passkey_salt),
                entries: encrypted_entries,
            }
        }
    }

    // `contents` is the contents of the file where the database was written
    // to, excluding the version (which is the first line in the file).
    pub fn database_from_str(
        contents: &str,
        passman_password_raw: &str,
    ) -> Result<Database, String> {
        let encrypted_database: EncryptedDatabase =
            serde_json::from_str(&contents).map_err(|_| "Failed to load database".to_string())?;

        // Check that the provided password is correct.
        let main_passkey_encrypted =
            utils::hex_to_bytes(&encrypted_database.main_passkey_encrypted);

        let password_verifying_hash = salt_and_hash(
            passman_password_raw.as_bytes(),
            &utils::hex_to_bytes(&encrypted_database.password_verifying_hash_salt)[..],
        );
        if utils::bytes_to_hex(&password_verifying_hash)
            != encrypted_database.password_verifying_hash
        {
            return Err("Invalid password.".to_string());
        }

        // Since the password is correct, decrypt the main encryption key (which is used for
        // actually encrypting the entries).
        let intermediate_key = salt_and_hash(
            passman_password_raw.as_bytes(),
            &utils::hex_to_bytes(&encrypted_database.intermediate_passkey_salt)[..],
        );
        let encryption_key: aes::MainKey = aes::decrypt(&main_passkey_encrypted, &intermediate_key)
            .map_err(|_| "Intermediate decryption failed".to_string())?[..32]
            .try_into()
            .unwrap();

        let password_verifying_hash = utils::extract_all_bytes!(
            utils::hex_to_bytes(&encrypted_database.password_verifying_hash),
            32
        )
        .map_err(|_| "Decryption Failed. The file appears to be corrupted.".to_string())?;
        let password_verifying_hash_salt = utils::extract_all_bytes!(
            utils::hex_to_bytes(&encrypted_database.password_verifying_hash_salt),
            16
        )
        .map_err(|_| "Decryption Failed. The file appears to be corrupted.".to_string())?;
        let intermediate_passkey_salt = utils::extract_all_bytes!(
            utils::hex_to_bytes(&encrypted_database.intermediate_passkey_salt),
            16
        )
        .map_err(|_| "Decryption Failed. The file appears to be corrupted.".to_string())?;

        // Decrypt the entries.
        let entries_bytes = aes::decrypt(
            &utils::hex_to_bytes(&encrypted_database.entries)[..],
            &encryption_key,
        )
        .map_err(|_| "Decrypting entries failed.".to_string())?;
        let entries_json = String::from_utf8(entries_bytes)
            .map_err(|_| "Error reading entries as UTF-8 after decryption.".to_string())?;
        let entries = serde_json::from_str::<Vec<Entry>>(&entries_json)
            .map_err(|_| "Error reading JSON after decryption".to_string())?;

        Ok(Database {
            encryption_key: encryption_key,
            main_passkey_encrypted: encrypted_database.main_passkey_encrypted.clone(),
            password_verifying_hash: password_verifying_hash,
            password_verifying_hash_salt: password_verifying_hash_salt,
            intermediate_passkey_salt: intermediate_passkey_salt,
            entries: entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{v1, Database};
    use indoc;
    use tempfile;

    //////////////// PRELUDE ////////////////
    struct Setup {
        pub password: &'static str,
        pub entry1: v1::Entry,
        pub entry2: v1::Entry,
        pub entry3: v1::Entry,
    }

    impl Setup {
        pub fn new() -> Self {
            let password = "Let me in";

            let entry1 = v1::Entry {
                id: 1, // When added to a database, the created Entry will likely have a different ID.
                username: "username".to_string(),
                password_raw: "password".to_string(),
                website: "google.com".to_string(),
                notes: "".to_string(),
            };
            let entry2 = v1::Entry {
                id: 34, // When added to a database, the created Entry will likely have a different ID.
                username: "janedoe".to_string(),
                password_raw: "keep-it-secret-keep-it-safe".to_string(),
                website: "https://www.github.com".to_string(),
                notes: "It's for GitHub".to_string(),
            };
            let entry3 = v1::Entry {
                id: 117, // When added to a database, the created Entry will likely have a different ID.
                username: "williamthemagnificent".to_string(),
                password_raw: "123".to_string(),
                website: "https://www.world-of-engineering.com".to_string(),
                notes: "This is for my beta website".to_string(),
            };

            Setup {
                password: password,
                entry1: entry1,
                entry2: entry2,
                entry3: entry3,
            }
        }
    }

    fn insert_entry(database: &mut Database, entry: &v1::Entry) {
        database.add(
            &entry.username,
            &entry.password_raw,
            &entry.website,
            &entry.notes,
        );
    }

    macro_rules! random_filename {
        ($base:expr, $random_digits_len:expr) => {{
            let random_str = [0u8; $random_digits_len]
                .iter()
                .map(|_| (('0' as u8) + (rand::random::<u8>() % 10)) as char)
                .fold("".to_string(), |mut result, ch| {
                    result.push(ch);
                    result
                });
            String::from($base) + &random_str
        }};
    }

    ///////////////// TESTS /////////////////
    #[test]
    fn salt_and_hash() {
        let password = "Keep it secret".as_bytes();
        let salt1 = "Keep it safe".as_bytes();
        let salt2 = "salty".as_bytes();

        let hash1 = super::salt_and_hash(&password, &salt1);
        let hash2 = super::salt_and_hash(&password, &salt2);
        let hash1_redo = super::salt_and_hash(&password, &salt1);

        assert_eq!(hash1, hash1_redo);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn encryption_and_decryption_zero_entries() {
        let setup = Setup::new();
        let database = Database::new(setup.password);
        let encrypted = database.to_str().unwrap();
        let decrypted_database = Database::from_str(&encrypted, setup.password).unwrap();

        assert_eq!(decrypted_database, database);
    }

    #[test]
    fn encryption_and_decryption_one_entry() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1);

        let encrypted = database.to_str().unwrap();
        let decrypted_database = Database::from_str(&encrypted, setup.password).unwrap();

        assert_eq!(decrypted_database, database);
    }

    #[test]
    fn encryption_and_decryption_multiple_entries() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1);
        insert_entry(&mut database, &setup.entry2);
        insert_entry(&mut database, &setup.entry3);

        let encrypted = database.to_str().unwrap();
        let decrypted_database = Database::from_str(&encrypted, setup.password).unwrap();

        assert_eq!(decrypted_database, database);
    }

    #[test]
    fn encrypt_and_decrypt_file() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1);
        insert_entry(&mut database, &setup.entry2);
        insert_entry(&mut database, &setup.entry3);

        let dir = tempfile::tempdir().unwrap();
        let filename = &dir
            .path()
            .join(random_filename!("test-file-", 16))
            .into_os_string()
            .into_string()
            .unwrap();
        database.write(filename).unwrap();
        let decrypted_database = Database::read(filename, setup.password);

        assert!(decrypted_database.is_ok());
        assert_eq!(decrypted_database.unwrap(), database);
    }

    #[test]
    fn add_and_remove_entries() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets Id 1
        insert_entry(&mut database, &setup.entry2); // Gets Id 2

        assert_eq!(database.entries.len(), 2);
        let r = database.remove(1);
        assert!(r.is_ok());
        assert_eq!(database.entries.len(), 1);
        insert_entry(&mut database, &setup.entry3); // Gets Id 1
        assert_eq!(database.entries.len(), 2);
    }

    #[test]
    fn remove_valid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets Id 1

        assert_eq!(database.entries.len(), 1);
        let r = database.remove(1);
        assert!(r.is_ok());
        assert_eq!(database.entries.len(), 0);
    }

    #[test]
    fn remove_invalid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets Id 1

        assert_eq!(database.entries.len(), 1);
        let r = database.remove(42);
        assert!(r.is_err());
        assert_eq!(database.entries.len(), 1);
    }

    #[test]
    fn short_form() {
        let setup = Setup::new();
        let entry1_short =
            "  1. username             google.com                                         ";
        let entry2_short =
            " 34. janedoe              https://www.github.com         It's for GitHub     ";
        let entry3_short =
            "117. williamthemagnifi... https://www.world-of-engine... This is for my be...";

        assert_eq!(setup.entry1.short_form(), entry1_short);
        assert_eq!(setup.entry2.short_form(), entry2_short);
        assert_eq!(setup.entry3.short_form(), entry3_short);
    }

    #[test]
    fn long_form() {
        let setup = Setup::new();

        let entry1_long = indoc::indoc! {"
            Username: username
            Password: password
            Website: google.com
            Notes:
        "};
        let entry2_long = indoc::indoc! {"
            Username: janedoe
            Password: keep-it-secret-keep-it-safe
            Website: https://www.github.com
            Notes: It's for GitHub
        "};
        let entry3_long = indoc::indoc! {"
            Username: williamthemagnificent
            Password: 123
            Website: https://www.world-of-engineering.com
            Notes: This is for my beta website
        "};

        // Allow for different leading or trailing whitespace, but everything
        // else must be verbatim.
        assert_eq!(setup.entry1.long_form().trim(), entry1_long.trim());
        assert_eq!(setup.entry2.long_form().trim(), entry2_long.trim());
        assert_eq!(setup.entry3.long_form().trim(), entry3_long.trim());
    }

    #[test]
    fn get_entry_long_form() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry2); // Gets ID 1.
        let id = 1;

        let computed = database.get_entry_long_form(id);
        let expected = setup.entry2.long_form();

        assert!(computed.is_ok());
        assert_eq!(computed.unwrap(), expected);
    }

    #[test]
    fn find_no_entries() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.
        insert_entry(&mut database, &setup.entry2); // Gets ID 2.
        insert_entry(&mut database, &setup.entry3); // Gets ID 3.

        let computed = database.find("not-a-substring-of-any-entry");
        let expected = "";

        assert_eq!(computed, expected);
    }

    #[test]
    fn find_one_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.
        insert_entry(&mut database, &setup.entry2); // Gets ID 2.
        insert_entry(&mut database, &setup.entry3); // Gets ID 3.

        let entry2 = v1::Entry {
            id: 2,
            ..setup.entry2
        };

        let computed = database.find("doe");
        let expected = entry2.short_form();

        assert_eq!(computed, expected);
    }

    #[test]
    fn find_multiple_entries() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.
        insert_entry(&mut database, &setup.entry2); // Gets ID 2.
        insert_entry(&mut database, &setup.entry3); // Gets ID 3.

        let entry2 = v1::Entry {
            id: 2,
            ..setup.entry2
        };
        let entry3 = v1::Entry {
            id: 3,
            ..setup.entry3
        };

        let computed = database.find("https");
        let expected = entry2.short_form() + "\n" + &entry3.short_form();

        assert_eq!(computed, expected);
    }

    #[test]
    fn set_username_valid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 1;
        let new_username = "inigomontoya";

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_ne!(entry.unwrap().username, new_username);

        let r = database.set_entry_username(id, new_username);
        assert!(r.is_ok());

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().username, new_username);
    }

    #[test]
    fn set_username_invalid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 35; // No entry in the database has this ID.
        let new_username = "inigomontoya";

        let r = database.set_entry_username(id, new_username);
        assert!(r.is_err());
    }

    #[test]
    fn set_password_valid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 1;
        let new_password = "youkilledmyfather";

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_ne!(entry.unwrap().password_raw, new_password);

        let r = database.set_entry_password(id, new_password);
        assert!(r.is_ok());

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().password_raw, new_password);
    }

    #[test]
    fn set_password_invalid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 35; // No entry in the database has this ID.
        let new_password = "youkilledmyfather";

        let r = database.set_entry_password(id, new_password);
        assert!(r.is_err());
    }

    #[test]
    fn set_website_valid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 1;
        let new_website = "preparetodie.com";

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_ne!(entry.unwrap().website, new_website);

        let r = database.set_entry_website(id, new_website);
        assert!(r.is_ok());

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().website, new_website);
    }

    #[test]
    fn set_website_invalid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 35; // No entry in the database has this ID.
        let new_website = "preparetodie.com";

        let r = database.set_entry_website(id, new_website);
        assert!(r.is_err());
    }

    #[test]
    fn set_notes_valid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 1;
        let new_notes = "*Repeats endlessly*";

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_ne!(entry.unwrap().notes, new_notes);

        let r = database.set_entry_notes(id, new_notes);
        assert!(r.is_ok());

        let entry = database.get_entry(id);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().notes, new_notes);
    }

    #[test]
    fn set_notes_invalid_entry() {
        let setup = Setup::new();
        let mut database = Database::new(&setup.password);
        insert_entry(&mut database, &setup.entry1); // Gets ID 1.

        let id = 35; // No entry in the database has this ID.
        let new_notes = "*Repeats endlessly*";

        let r = database.set_entry_notes(id, new_notes);
        assert!(r.is_err());
    }
}

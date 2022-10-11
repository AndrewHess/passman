use crate::database::Database;
use dirs;
use indoc;
use std::io::{self, BufRead, Write};

// All data written to disk is in this file in the user's home directory.
const FILENAME: &str = ".passman";
const MAX_LOGGIN_ATTEMPTS: u8 = 3;

pub fn start() {
    println!("Welcome to Passman");

    let mut path = dirs::home_dir().expect("Error: Unable to access home directory");
    path.push(FILENAME);
    let path = path.as_path();

    let path_string = path
        .to_str()
        .expect("Internal error constructing filename.")
        .to_string();

    // Check whether an account already exists.
    let database = match path.exists() {
        false => create_password(),
        true => login(&path_string),
    };

    if let Some(mut database) = database {
        println!("Enter a command, or the word help for available commands.");
        main_loop(&mut database);
        save(&database, &path_string);
    }
}

// Return the new database if a password is created, or None if no password was created.
fn create_password() -> Option<Database> {
    println!(indoc::indoc! {"
        Looks like this is your first time using Passman for this computer user. You need to \
        create a password to secure your login credentials.

        It's recommended to create a password that is comprised of several random words. Such \
        passwords are typically both easier to remember and harder for someone else to guess than \
        single-word passwords with common substitutions (like the number 0 instead of the letter \
        O). You can also use capitalization and numbers to make your password more secure.

        The password you create must be at least 16 characters long. Enter it below."
    });

    let password;
    loop {
        prompt_for_input();
        let mut potential_password = read_trimmed_line();
        println!("password: '{}'", potential_password); // todo deleteme

        while potential_password.len() < 16 {
            println!("Your password must be at least 16 characters long. Enter it below.");
            prompt_for_input();
            potential_password = read_trimmed_line();
        }

        println!("Re-enter your password.");
        prompt_for_input();
        let password_again = read_trimmed_line();

        if potential_password == password_again {
            password = potential_password;
            break;
        } else {
            println!("Those passwords do not match. Create your password.");
        }
    }

    println!("Password created.");
    Some(Database::new(&password))
}

// Return the saved database if login succeeds, otherwise None.
fn login(path_of_database: &str) -> Option<Database> {
    for _ in 0..MAX_LOGGIN_ATTEMPTS {
        print_and_flush("Enter your password: ");
        let password = read_trimmed_line();
        match Database::read(path_of_database, &password) {
            Ok(database) => {
                println!("Login successful.");
                return Some(database);
            }
            Err(y) => println!("Failed to open database: {}", y),
        }
    }

    println!("Too many failed attempts.");
    None
}

fn main_loop(database: &mut Database) {
    let mut is_quitting = false;

    while !is_quitting {
        prompt_for_input();
        process_command(database, &read_trimmed_line(), &mut is_quitting);
    }
}

fn save(database: &Database, filename: &str) {
    database
        .write(filename)
        .unwrap_or_else(|err| println!("Error saving data: {}", err))
}

fn prompt_for_input() {
    print_and_flush("> ")
}

fn print_and_flush(line: &str) {
    print!("{}", line);
    io::stdout()
        .flush()
        .unwrap_or_else(|_| eprintln!("Internal error flushing line"))
}

fn read_trimmed_line() -> String {
    let line = io::stdin().lock().lines().next().unwrap().unwrap(); // TODO: handle errors.
    line.trim().to_string()
}

fn process_command(database: &mut Database, cmd: &str, is_quitting: &mut bool) {
    match cmd {
        "help" => {
            println!("help: Displays available commands");
            println!("add: Add a password to the database");
            println!("list: Display a preview of all entries");
            println!("quit: Quits the program");
        }
        "add" => add_entry(database),
        "list" => println!("{}", database.find("")),
        "quit" => {
            println!("Bye!");
            *is_quitting = true;
        }
        _ => println!("Invalid command. Try again."),
    }
}

fn add_entry(database: &mut Database) {
    println!(indoc::indoc! {"\
        Enter the credentials you want to store. The password must not be left empty, but you \
        can skip all but one of the other fields."
    });

    let final_password: String;
    loop {
        print_and_flush("Password: ");
        let password = read_trimmed_line();

        if password.is_empty() {
            println!("Your password must not be empty");
            continue;
        }

        // Ensure no leading or trailing whitespace. This would make it difficult to see what the
        // password is when it's printed.
        if password.len() != password.trim().len() {
            println!(
                "Your password must not have leading or trailing whitespace (spaces, tabs, etc.)"
            );
            continue;
        }

        // This is a valid password.
        final_password = password.to_string();
        break;
    }

    let final_username: String;
    let final_url: String;
    let final_notes: String;
    loop {
        print_and_flush("Username: ");
        let username = read_trimmed_line();

        print_and_flush("URL: ");
        let url = read_trimmed_line();

        print_and_flush("Notes: ");
        let notes = read_trimmed_line();

        if username.is_empty() && url.is_empty() && notes.is_empty() {
            println!("You must add a username, URL, and/or notes");
            continue;
        }

        // These entries are valid.
        final_username = username;
        final_url = url;
        final_notes = notes;
        break;
    }

    database.add(&final_username, &final_password, &final_url, &final_notes);
    println!("Entry added.");
}

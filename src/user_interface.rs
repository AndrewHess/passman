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
    let (cmd_first, cmd_rest) = match cmd.find(char::is_whitespace) {
        None => (cmd, ""),
        Some(x) => (&cmd[..x], &cmd[(x + 1)..]),
    };

    // The argument won't always be an ID, but it will be for several cases.
    let id = cmd_rest.parse::<usize>();
    let bad_id_msg = format!(
        "'{}' is not an integer. Make sure to not include a decimal.",
        cmd_rest
    );
    let print_long_form = || {
        // Return true iff the id is valid.
        match id {
            Ok(id) => match database.get_entry_long_form(id) {
                Ok(s) => {
                    println!("{}", s);
                    return true;
                }
                Err(_) => {
                    println!("Invalid ID");
                    return false;
                }
            },
            Err(_) => {
                println!("{}", bad_id_msg);
                return false;
            }
        }
    };

    match cmd_first {
        "help" => {
            println!("help: Displays available commands");
            println!("add: Add a password to the database");
            println!("edit-notes <id>: Edit the notes for the specified entry");
            println!("edit-password <id>: Edit the password for the specified entry");
            println!("edit-url <id>: Edit the URL for the specified entry");
            println!("edit-username <id>: Edit the username for the specified entry");
            println!("find <text>: Display a preview of all entries containing <text>");
            println!("list: Display a preview of all entries");
            println!("show <id>: Display all details of the specified entry");
            println!("quit: Quits the program");
        }
        "add" => add_entry(database),
        "edit-notes" => {
            let id_is_usize = print_long_form();

            if id_is_usize {
                print_and_flush("New notes: ");
                let notes = read_trimmed_line();
                let r = database.set_entry_notes(id.unwrap(), &notes);

                if r.is_err() {
                    println!("Error changing the notes");
                }
            }
        }
        "edit-password" => {
            let id_is_usize = print_long_form();

            if id_is_usize {
                print_and_flush("New password: ");
                let password = read_trimmed_line();
                let r = database.set_entry_password(id.unwrap(), &password);

                if r.is_err() {
                    println!("Error changing the password");
                }
            }
        }
        "edit-url" => {
            let id_is_usize = print_long_form();

            if id_is_usize {
                print_and_flush("New url: ");
                let url = read_trimmed_line();
                let r = database.set_entry_website(id.unwrap(), &url);

                if r.is_err() {
                    println!("Error changing the url");
                }
            }
        }
        "edit-username" => {
            let id_is_usize = print_long_form();

            if id_is_usize {
                print_and_flush("New username: ");
                let username = read_trimmed_line();
                let r = database.set_entry_username(id.unwrap(), &username);

                if r.is_err() {
                    println!("Error changing the username");
                }
            }
        }
        "find" => println!("{}", database.find(cmd_rest)),
        "list" => println!("{}", database.find("")),
        "show" => {
            let s = match id {
                Ok(id) => database
                    .get_entry_long_form(id)
                    .unwrap_or_else(|_| "Invaid ID".to_string()),
                Err(_) => bad_id_msg,
            };
            print!("{}", s);
        }
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

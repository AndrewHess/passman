use crate::database::Database;
use dirs;
use indoc;
use std::io::{self, BufRead, Write};
use std::path::Path;

// All data written to disk is in this file in the user's home directory.
const FILENAME: &str = ".passman";
const MAX_LOGGIN_ATTEMPTS: u8 = 3;

#[derive(Debug, PartialEq)]
enum State {
    CheckingForAccount,
    CreatingPassword,
    LoggingIn(String),
    LoggedIn(Database),
    Exiting,
}

pub fn start() {
    println!("Welcome to Passman");
    println!("Enter the word help for available commands");

    let state = check_for_account();
    let state = match state {
        State::CreatingPassword => create_password(),
        State::LoggingIn(path_to_database) => login(&path_to_database),
        State::Exiting => return,
        _ => panic!("Unexpected state after check_for_account(): {:?}", state),
    };

    match state {
        State::LoggedIn(mut database) => main_loop(&mut database),
        State::Exiting => (),
        unexpected => println!("Unexpected state: {:?}", unexpected),
    }
}

// Searches for FILENAME. If it finds it, the user has an account and should enter
// their password. If the file does not exist, the user should create an account.
fn check_for_account() -> State {
    let mut path_buf = match dirs::home_dir() {
        Some(dir) => dir,
        None => {
            println!("Error: unable to access home directory");
            return State::Exiting;
        }
    };

    path_buf.push(FILENAME);
    let path = path_buf.as_path();

    return match path.exists() {
        true => State::LoggingIn(
            path.to_str()
                .expect("Internal error constructing filename.")
                .to_string(),
        ),
        false => State::CreatingPassword,
    };
}

fn create_password() -> State {
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

    State::LoggedIn(Database::new(&password))
}

fn login(path_to_database: &str) -> State {
    let password_prompt = "Enter your password: ";
    for i in 0..MAX_LOGGIN_ATTEMPTS {
        print_and_flush(password_prompt);
        let password: String = read_trimmed_line()
            .strip_prefix(&password_prompt)
            .expect("Internal error reading password")
            .to_string();

        println!("password: {}", password);
        match Database::read(path_to_database, &password) {
            Ok(database) => return State::LoggedIn(database),
            Err(y) => println!("Invalid password."),
        }
    }

    println!("Too many failed attempts.");
    State::Exiting
}

fn main_loop(database: &mut Database) {
    let mut is_quitting = false;

    while !is_quitting {
        prompt_for_input();
        process_command(database, &read_trimmed_line(), &mut is_quitting);
    }
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
            println!("quit: Quits the program");
        }
        "quit" => {
            println!("Bye!");
            *is_quitting = true;
        }
        _ => println!("Invalid command. Try again."),
    }
}

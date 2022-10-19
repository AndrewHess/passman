# Passman
Passman is a self-hosted command-line password manager.

## Design Documents
https://young-truffle-276.notion.site/Password-Manager-b28f97a578754990a26c776854bd3b26

## Installation
```
# Clone the repository.
https://github.com/AndrewHess/passman.git
cd passman

# Compile.
cargo build --release

# Copy the executable to your desired location.
sudo cp target/release/passman /opt
```

Next create an alias by adding `alias passman=/opt/passman` to your `~/.bashrc` or `~/.zshrc` and activate it via `source ~/.bashrc` or `source ~/.zshrc`.

Now you can use the `passman` command in the terminal from any directory to access the database for your user.
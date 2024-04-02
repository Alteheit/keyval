# Architecture of the keyval repository

I basically used keyval to practice my Go. As such, the organization of this repository is incredibly simple and arguably horrifying: everything is in `main.go`.

The code within `main.go` is broken up into some functions. The most important function by far is `dispatcher`. This reads the shape of your CLI args and executes the appropriate branch.

- Other functions are there as helpers:
    - `marshalDb` takes a map[string]string and gives back a single string, composed of records delimited by the Unicode record separator character. Each record's fields are delimited by the Unicode field separator character.
    - `unmarshalDb` takes a string, composed of records delimited by the Unicode record separator character, and returns a map[string]string. Each record's fields are delimited by the Unicode field separator character.
    - `writeDb` takes a string and writes it to the database file, which is `~/.keyval/db`.
    - `readDb` reads the database file, which is `~/.keyval/db`, and returns a string.
    - `readKeyFromEnvironment` reads the encryption key from the environment variable `KEYVAL_KEY`. It exits the program if it can't find one.
    - `encrypt` takes a string and a key and returns some ciphertext as a string.
    - `decrypt` takes some ciphertext and a key and returns the decrypted string.
    - `ensureDotFolder` makes sure that the `.keyval` dotfolder is present in your home directory. It runs every time `writeDb` and `readDb` are called.

It's a pretty horrible codebase architecture, but I've found that it strangely makes me write things really quickly. I have come back to this project a few times to add new features and have found myself able to do so really quickly as well; I can still understand it when I come back to it since there's very little interleaving between components.

# keyval

Key-value (`keyval`) is a simple CLI utility to get and set keys and values.

This is my personal tool for keeping secrets on my local machine.

## Prerequisites

- The environment variable KEYVAL_KEY needs to be set.
- Your user directory must not have an important `.keyval` dotfolder.

## Installation

1. Clone this repository.
2. Run `go build`.
3. Move the compiled `keyval` binary to somewhere on your PATH.

## Usage

To set a value:

```shell
keyval set your-key your-value
```

To _secretly_ set a value:

```shell
keyval sset your-key
# You will then be prompted for a secret value
```

To get a value:

```shell
keyval get your-key
```

To list the keys you've set:

```shell
keyval list
```

To delete a key and its value:

```shell
keyval delete your-key
```

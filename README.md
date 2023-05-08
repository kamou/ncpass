# ncpass

Simple password cli tool for the nextcloud passwords app

## Usage
### Basic commands
List all available passwords:
```sh
ncpass list password
```

this will output the list of password label followed by their ID.
```
Name1 [db3fe6c9-038c-433e-a8c8-fd98d012ea2e]
Name2 [870d768a-fde0-41dd-b92c-63ddfa7134ed]
Name3 [0f6143ed-98c1-4de2-894a-094b6e833c34]
[...]
```
to actually get the password details:
```sh
ncpass get password 0f6143ed-98c1-4de2-894a-094b6e833c34
```
this will output the whole password details (label, uername, password, url, notes, etc...)


### Raw API
these are the commands I use with rofi/demenu, but to get a bit more features, you can still use the raw command which is a direct access to the passwords REST api:

list all available passwords with all details.
```sh
ncpass raw password list
```

you can still request to show a sinble password using the show action:
```sh
ncpass raw password show --id=870d768a-fde0-41dd-b92c-63ddfa7134ed
```

or for creating a password:
```sh
ncpass raw password create --label="Some Label" --username="ak42" --password="Sup3rS3cr3tP@55w0rd"
```

check the [developer handbook](https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Index) for more detail.
All commands are not yet implemented.

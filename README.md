# Phone book

The program `phone_book.c` is a partially completed phone book
program. It is a command line program that will maintain a database of
phone numbers and names in a file `directory.db`. 

It can be used in the following way. 

1. `./phone_book add name number`
   This command is used to add the `name` and `number` to the
   database. If the database file (
   
2. `./phone_book list`
   This command will list all the users and numbers in the system
   
3. `./phone_book search name`
   This command will search for the entry with name `name` and print
   the phone number if `name` exists. Otherwise it will print `no
   match` and exit with a non-zero status.
   
4. `./phone_book delete name`
   This command will search for the entry with name `name` and delete
   it from the database if `name` exists. Otherwise it will print `no
   match` and exit with a non-zero status.

# Design notes

The program loads the entries in the database into a linked list. Each
node of the list contains the name and phone number. 

The program has decent error checking. It will abort if you try to
list when the database file is non existent. It will also print proper
error messages if you type a wrong or malformed command. 

The program allocates memory to create the linked list. It should be
fully freed before the program exits. `valgrind` should show no leaks possible.

# Example usage

A pre compiled version of the program with all the features mentioned
below is available in the repository as `good_phone_book`. You can use
this to compare the output of your program.

## Error handling

    %  ls directory.db
    /bin/ls: cannot access 'directory.db': No such file or directory                                              
    % ./phone_book list
    Couldn't open database file: No such file or directory
    % ./phone_book search john
    Couldn't open database file: No such file or directory
    % ./phone_book delete john
    Couldn't open database file: No such file or directory

## Adding and listing

    % ./phone_book add john 1234567890
    % ./phone_book list
    john                 : 1234567890
    Total entries :  1
    % ./phone_book add james 0987654321
    % ./phone_book list
    john                 : 1234567890
    james                : 0987654321
    Total entries :  2

## Searching

    % ./phone_book search mary
    no match
    % ./phone_book search james
    0987654321

## Deleting

    % ./phone_book add jack 5432167890
    % ./phone_book delete mary
    no match
    % ./phone_book list
    john                 : 1234567890
    james                : 0987654321
    jack                 : 5432167890
    Total entries :  3
    % ./phone_book delete james
    % ./phone_book list
    john                 : 1234567890
    jack                 : 5432167890
    Total entries :  2
    % ./phone_book delete john
    % ./phone_book list
    jack                 : 5432167890
    Total entries :  1

# Tasks

There is a comment "TBD" in various parts of the phone_book.c file to
indicate what parts of the code need to be implemented.

1. The `total entries` is not currently printed by the `list`
   command. This needs to be fixed. 
1. The delete functionality has to be implemented similar to the others
   (including error checking etc.). The command line parsing works but
   it doesn't actually do any deletion. Make sure that all files are
   closed and all memory is freed.
1. The search functionality is not implemented. The command is also
   not recognised. This needs to be fixed. Make sure that all files are
   closed and all memory is freed.
1. The `free_entries` function should walk through the linked list and
   free all the nodes in it. It's not implemented. You can check to
   see if it's properly implemented and running 
   
         valgrind ./phone_book search jack
         
   The output of `valgrind` should have a line like this. This will
   happen only if `free_entries` is properly implemented and all
   memory is freed.
   
           All heap blocks were freed -- no leaks are possible


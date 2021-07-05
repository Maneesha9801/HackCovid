#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *DB="directory.db";

struct entry0 {
  char name[20];
  char phone[20];
  struct entry0 *next;
};

typedef struct entry0 entry;

/* Command handlers */
void add(char *, char *);
int search(FILE *,char *);
void list(FILE *);
int delete(FILE *, char *);

/* Utility functions  */
FILE * open_db_file(); /* Opens the database file. Prints error and
                          quits if it's not available */
void print_usage(char *, char *);  /* Prints usage */
entry *load_entries(FILE *);         /* Load all entries from the
                                      database file. Returns pointer
                                      to first entry */
entry *create_entry_node(char *, char *);  /* Create a new entry
                                              node. Has to be freed by
                                              user. */
void free_entries(entry *); /* TBD Given the first node of a linked list
                               of entries, will free all the nodes */ 

void write_all_entries(entry *); /* Given the first node of a linked
                                    list of entries, will delete the
                                    database file on the disk and save
                                    the given entries into the file */


int main(int argc, char *argv[]) {
  if (argc == 1) {
    print_usage("Insufficient arguments", argv[0]);
    exit(1);
  } 

  if (strcmp(argv[1], "add") == 0) {   /* Handle add */
    if (argc != 4) {
      print_usage("Improper arguments for add", argv[0]);
      exit(1);
    }
    char *name = argv[2];
    char *phone = argv[3];
    add(name, phone);
    exit(0);
  } else if (strcmp(argv[1], "list") == 0) {  /* Handle list */
    if (argc != 2) {
      print_usage("Improper arguments for list", argv[0]);
      exit(1);
    }
    FILE *fp = open_db_file();
    list(fp);
    fclose(fp);
    exit(0);
  } else if (strcmp(argv[1], "search") == 0) {  /* Handle search */
    printf("NOT IMPLEMENTED!\n"); /* TBD  */
  } else if (strcmp(argv[1], "delete") == 0) {  /* Handle delete */
    if (argc != 3) {
      print_usage("Improper arguments for delete", argv[0]);
      exit(1);
    }
    FILE *fp = open_db_file();
    char *name = argv[2];
    if (!delete(fp, name)) {
      printf("no match\n");
      fclose(fp);
      exit(1);
    }
    fclose(fp);
    exit(0);
  } else {
    print_usage("Invalid command", argv[0]);
    exit(1);
  }
}

FILE *open_db_file() {
  FILE *fp=fopen(DB, "r");
  if (fp == NULL) {
    perror("Couldn't open database file");
    exit(1);
  }
  return fp;
}
  
void free_entries(entry *p) {
  /* TBD */
  printf("Memory is not being freed. This needs to be fixed!\n");  
}

void print_usage(char *message, char *progname) {
  printf("Error : %s\n", message);
  printf("Usage: %s command arguments\n", progname);
  printf("\nAvailable commands: \n-------------------\n");
  printf("add name phonenumber\n");
  printf("    Used to add a new name to the database.\n    name and phone number should not have any\n    spaces in them\n");
  printf("search name\n");
  printf("    Prints the phone number of the given name\n    if it's there in the database. Prints\n    'no match' if not found\n");
  printf("list\n");
  printf("    Lists all names and phone numbers in the\n    system along with a total count at the end.\n");
  printf("delete name\n");
  printf("    Deletes the entry for the name in the database.\n    Prints 'no match' if there's no such name.\n");
}

entry *
create_entry_node(char *name, char *phone) {
  entry *ret;
  ret = malloc(sizeof(entry));
  strcpy(ret->name, name);
  strcpy(ret->phone, phone);
  ret->next = NULL;
  return ret;
}


entry *load_entries(FILE *fp) {
  char name[20], phone[20];
  memset(name, '\0', 20);
  memset(phone, '\0', 20);
  entry *ret = NULL;
  entry *current = NULL;
  entry *tmp = NULL;
  /* Description of %20[^,\n]
     % is the start of the specifier (like %s, %i etc.)

     20 is the maximum number of characters that this will take. We
        know that names and phone numbers will be 20 bytes maximum so
        we limit it to that. %20s will read in 20 character strings
        (including the , to separate the name and phone number. That's
        why we use

    [^,\n] Square brackets are used to indicate a set of allowed
           characters [abc] means only a, b, or c. With the ^, it's
           used to specify a set of disallowed characters. So [^abc]
           means any character *except* a, b, or c. [^,] means any
           character except a , [^,\n] means any character except a
           comma(,) or a newline(\n).

    %20[^,\n] will match a string of characters with a maximum length
     of 20 characters that doesn't have a comma(,) or a newline(\n).
  */        
  while (fscanf(fp, "%20[^,\n],%20[^,\n]\n", name, phone) != EOF) {
    tmp = create_entry_node(name, phone);
    if (ret == NULL)
      ret = tmp;
    else
      current->next = tmp;
    current = tmp;
  }
  return ret;
}

void write_all_entries(entry * p) {
  FILE *fp = fopen(DB, "w");
  while (p != NULL) {
    fprintf(fp, "%s,%s\n", p->name, p->phone);
    p = p->next;
  }
  fclose(fp);
}


void add(char *name, char *phone) {
  FILE *fp = fopen(DB, "a");
  fprintf(fp, "%s,%s\n", name, phone);
  fclose(fp);
}

void list(FILE *db_file) {
  entry *p = load_entries(db_file);
  entry *base = p;
  while (p!=NULL) {
    printf("%-20s : %10s\n", p->name, p->phone);
    p=p->next;
  }
  /* TBD print total count */
  free_entries(base);
}


int delete(FILE *db_file, char *name) {
  entry *p = load_entries(db_file);
  entry *base = p;
  entry *prev = NULL;
  entry *del = NULL ; /* Node to be deleted */
  int deleted = 0;
  while (p!=NULL) {
    if (strcmp(p->name, name) == 0) {
      /* Matching node found. Delete it from the linked list.
         Deletion from a linked list like this
   
             p0 -> p1 -> p2
         
         means we have to make p0->next point directly to p2. The p1
         "node" is removed and free'd.
         
         If the node to be deleted is p0, it's a special case. 
      */

      /* TBD */
    }
  }
  write_all_entries(base);
  free_entries(base);
  return deleted;
}

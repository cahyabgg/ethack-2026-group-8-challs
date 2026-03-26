#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 16
#define NOTES_PER_USER 5


struct User *users[MAX_USERS] = {NULL};

struct Note *user_notes[MAX_USERS][NOTES_PER_USER] = {NULL};
struct NoteOps;

struct User {
    char username[24];
    struct NoteOps *vtable; 
};

struct NoteOps {
    void (*view_notes)(struct Note *);
    void (*logout)(void);
};

struct Note {
    char content[64];
};

int session_id = -1;

void view_notes_impl(struct Note *note) {
    if (session_id == -1 || note == NULL) return;
    size_t len = strlen(note->content);

    char out_buf[128];
    snprintf(out_buf, sizeof(out_buf), "Note (%zu bytes): %s\n", len, note->content);
    printf(out_buf);
}

void logout_impl() {
    printf("\nSession closed for user %d.\n\n", session_id);
    session_id = -1;
}

struct NoteOps default_vtable = {
    .view_notes = view_notes_impl,
    .logout = logout_impl
};

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void register_account() {
    int i = -1;
    for (int j = 0; j < MAX_USERS; j++) {
        if (users[j] == NULL) { i = j; break; }
    }
    if (i == -1) return;

    users[i] = (struct User *)malloc(sizeof(struct User));
    printf("Username: ");
    fgets(users[i]->username, 24, stdin);
    users[i]->username[strcspn(users[i]->username, "\n")] = 0;
    users[i]->vtable = &default_vtable;
    printf("Account registered with ID %d.\n", i);
}

void login() {
    char name[32];

    printf("Login username: ");
    fgets(name, 32, stdin);
    name[strcspn(name, "\n")] = 0;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i] && strcmp(users[i]->username, name) == 0) {
            session_id = i;
            printf("Logged in as: ");
            printf(users[i]->username); // Format string leak
            printf("\n");
            return;
        }
    }
}

void create_note(int u_id) {
    int n_idx;
    printf("Create at index: ");
    scanf("%d", &n_idx);
    getchar();

    if (user_notes[u_id][n_idx] == NULL) {
        user_notes[u_id][n_idx] = (struct Note *)malloc(sizeof(struct Note));
    }
    
    printf("Content: ");
    read(0, user_notes[u_id][n_idx]->content, 64);
}

void edit_note(int u_id) {
    int n_idx;
    printf("Edit index: ");
    scanf("%d", &n_idx);
    getchar(); 

    if (user_notes[u_id][n_idx] == NULL) {
        printf("Note does not exist.\n");
        return;
    }

    volatile size_t limit = 256; 
    printf("New content: ");
    for (int i = 0; i < limit; i++) {
        if (read(0, &user_notes[u_id][n_idx]->content[i], 1) <= 0) break;
        if (user_notes[u_id][n_idx]->content[i] == '\n') { 
            user_notes[u_id][n_idx]->content[i] = '\0'; 
            break; 
        }
    }
}

void view_one_note(int u_id) {
    int n_idx;
    printf("View index: ");
    scanf("%d", &n_idx);
    getchar();

    if (user_notes[u_id][n_idx]) {
        users[u_id]->vtable->view_notes(user_notes[u_id][n_idx]);
    }
}

void view_all_notes(int u_id) {
    printf("--- Batch View for %s ---\n", users[u_id]->username);
    for (int n_idx = 0; n_idx < NOTES_PER_USER; n_idx++) {
        if (user_notes[u_id][n_idx]) {
            printf("[%d] ", n_idx);
            users[u_id]->vtable->view_notes(user_notes[u_id][n_idx]);
        }
    }
}

void user_menu() {
    int choice;
    while (session_id != -1) {
        printf("1. Create Note\n");
        printf("2. Edit Note\n");
        printf("3. View One Note\n");
        printf("4. View All Notes\n");
        printf("5. Logout\n");
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        getchar();

        switch(choice) {
            case 1: create_note(session_id); break;
            case 2: edit_note(session_id); break;
            case 3: view_one_note(session_id); break;
            case 4: view_all_notes(session_id); break;
            case 5: users[session_id]->vtable->logout(); break;
            default: break;
        }
    }
}

int main() {
    init();
    while (1) {
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("> ");

        int c;
        if (scanf("%d", &c) != 1) break;
        getchar();
        if (c == 1) register_account();
        else if (c == 2) login();
        else exit(0);
        if (session_id != -1) user_menu();
    }
    return 0;
}
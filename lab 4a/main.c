#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int key;
    struct node *left, *right, *previous, *next, *parent;
    char *info;
} node_t;

typedef node_t *node_p;

char *get_str(int *len) {
    char buf[81] = {0};
    char *res = NULL;
    *len = 0;
    int n = 0;
    do {
        n = scanf("%80[^\n]", buf);
        if (n < 0) {
            if (!res) {
                return NULL;
            }
        } else if (n > 0) {
            int chunk_len = strlen(buf);
            int str_len = *len + chunk_len;
            res = (char *) realloc(res, (str_len + 1)*sizeof(char));
            memcpy(res + *len, buf, chunk_len);
            *len = str_len;
        } else {
            scanf("%*c");
        }
    } while (n > 0);

    if (*len > 0) {
        res[*len] = '\0';
    } else {
        res = calloc(1, sizeof(char));
    }

    return res;
}

node_p node_create(char *info) {
    node_p n = malloc(sizeof(node_t));
    n->info = info;
    n->left = NULL;
    n->right = NULL;
    n->previous = NULL;
    n->next = NULL;
    n->parent = NULL;
    return n;
}

void node_free(node_p *p_n){
    if (*p_n) {
        if ((*p_n)->info)
            free((*p_n)->info);
        free(*p_n);
        *p_n = NULL;
    }
}

void tree_free(node_p *p_tree){
    if (!(*p_tree))
        return;
    node_p n1, n2;
    n1 = (*p_tree)->left;
    n2 = (*p_tree)->right;
    node_free(p_tree);
    tree_free(&n1);
    tree_free(&n2);
}

node_p tree_find_previous(node_p n, int key) {
    node_p res = n;
    while (key < res->key){
        res = res->previous;
        if (!res)
            break;
    }
    return res;
}

node_p tree_find_next(node_p n, int key) {
    node_p res = n;
    while (key > res->key){
        res = res->next;
        if (!res)
            break;
    }
    return res;
}

node_p tree_find_first(node_p n) {
    node_p res = n;
    while (res->previous){
        res = res->previous;
    }
    return res;
}

node_p tree_find_last(node_p n) {
    node_p res = n;
    while (res->next){
        res = res->next;
    }
    return res;
}

node_p tree_find_node(node_p tree, int key){
    node_p res = tree;
    while (key != res->key){
        if (key < res->key){
            res = res->previous;
        } else {
            res = res->next;
        }
        if (!res)
            break;
    }
    return res;
}

char *tree_add(node_p *p_tree, node_p *p_n){
    char *res = NULL;
    node_p n = *p_n;
    if ((*p_tree) == NULL) {
        *p_tree = n;
        if (n->parent){
            if (n->key < (n->parent)->key){
                n->next = n->parent;
                node_p prev = tree_find_previous(n->parent, n->key);
                n->previous = prev;
                if (prev)
                    prev->next = n;
                (n->parent)->previous = n;
            } else {
                n->previous = n->parent;
                node_p next = tree_find_next(n->parent, n->key);
                n->next = next;
                if (next)
                    next->previous = n;
                (n->parent)->next = n;
            }
        }
    } else {
        if ((*p_tree)->key == n->key){
            res = (*p_tree)->info;
            (*p_tree)->info = n->info;
            n->info = NULL;
            node_free(p_n);
        } else {
            n->parent = *p_tree;
            if (n->key < (*p_tree)->key) {
                res = tree_add(&((*p_tree)->left), p_n);
            } else {
                res = tree_add(&((*p_tree)->right), p_n);
            }
        }
    }
    return res;
}

void node_set_next(node_p n, node_p n_next){
    if (n)
        n->next = n_next;
}

void node_set_previous(node_p n, node_p n_previous){
    if (n)
        n->previous = n_previous;
}

void node_clear_parent(node_p n){
    if (n) {
        if (n->parent) {
            if (n->parent->key < n->key) {
                n->parent->right = NULL;
            } else
                n->parent->left = NULL;
        }
        n->parent = NULL;
    }
}

void node_set_parent(node_p n, node_p n_parent){
    if (n) {
        n->parent = n_parent;
        if (n_parent) {
            if (n_parent->key < n->key) {
                n_parent->right = n;
            } else {
                n_parent->left = n;
            }
        }
    } else {

    }
}

node_p node_find_next1(node_p n){
    node_p res = n->next;
    while ((res->right)&&(res->left)) {
        res = res->next;
    }
    return res;
}

void tree_delete_node(node_p *tree, int key){
    node_p n = tree_find_node(*tree, key);
    if (n) {
        if ((!(n->left)) && (!(n->right))) { //Нет ни правого, ни левого поддеревьев
            if (!(n->parent)) //Если n был корнем
                *tree = NULL;
            node_clear_parent(n);
        } else {
            if (!((n->left)) != (!(n->right))) { //Есть только левое или только правое
                node_p n1 = n->left;
                if (!n1)
                    n1 = n->right;
                node_set_parent(n1, n->parent);
                if (!(n->parent)) //Если n был корнем
                    *tree = n1;
            } else {
                //Есть и левый, и правый
                node_p n1 = node_find_next1(n);
                if (n1->parent->left == n1) {
                    n1->parent->left = NULL;
                }
                if (n1->parent->right == n1) {
                    n1->parent->right = NULL;
                }
                node_set_parent(n1, n->parent);
                if (n->left) {
                    node_set_parent(n->left, n1);
                }
                if (n->right){
                    node_set_parent(n->right, n1);
                }
                node_set_parent(n->left, n1);
                if (!(n->parent)) { //Если n был корнем
                    *tree = n1;
                }
            }
        }
        node_set_next(n->previous, n->next);
        node_set_previous(n->next, n->previous);
        node_free(&n);
    }
}

void ask_main_menu_action(int *action){
    printf("Select action: 1 - add, 2 - delete, 3 - print, 4 - show tree, 0 - exit\n");
    scanf("%d", action);
}

void call_menu_tree_add(node_p *tree){
    printf("input key\n");
    int key;
    scanf("%d", &key);
    printf("Input info\n");
    scanf("\n");
    int len;
    char *info = get_str(&len);
    node_p n = node_create(info);
    n->key = key;
    char *old_info = tree_add(tree, &n);
    if (old_info) {
        printf("%s\n", old_info);
        free(old_info);
    }
}

void call_menu_tree_delete(node_p *tree){
    printf("Input key of the node to delete\n");
    int key;
    scanf("%d",&key);
    tree_delete_node(tree, key);
}

void tree_print_key(node_p tree, int key){
    node_p n = tree;
    if (key < n->key) {
        while (key < n->key){
            n = n->previous;
            if (!(n->previous)&&(key < n->key)){
                printf("Invalid key\n");
                return;
            }
        }
    } else {
        while (key >= n->key){
            n = n->next;
            if (!(n->next)&&(key > n->key)){
                break;
            }
        }
        if (key < n->key)
            n = n->previous;
    }
    while (n) {
        printf("key: %d, info: %s\n", n->key, n->info);
        n = n->previous;
    }
}

void tree_print_whole(node_p tree){
    node_p n = tree_find_last(tree);
    while (n) {
        printf("key: %d, info: %s\n", n->key, n->info);
        n = n->previous;
    }
}

void call_menu_tree_print(node_p tree){
    if (!(tree)){
        printf("The tree doesn't exist");
        return;
    }
    printf("Select mode: 1 - by key, any else - whole tree\n");
    int mode;
        scanf("%d", &mode);
        if (mode == 1) {
            int key;
            printf("Input key\n");
            scanf("%d", &key);
            tree_print_key(tree, key);
        } else {
            tree_print_whole(tree);
        }
}

void call_menu_tree_show(node_p tree, int level){
    if (tree){
        call_menu_tree_show(tree->left, level + 1);
        for (int i = 0; i < level; i++){
            printf("  ");
        }
        printf("%d\n", tree->key);
        call_menu_tree_show(tree->right, level + 1);
    }
}

int main() {
    node_p tree = NULL;
    int action = 1;
    while (action != 0) {
        ask_main_menu_action(&action);
        switch (action) {
            case 0:
                break;
            case 1:
                call_menu_tree_add(&tree);
                break;
            case 2:
                call_menu_tree_delete(&tree);
                break;
            case 3:
                call_menu_tree_print(tree);
                break;
            case 4:
                call_menu_tree_show(tree, 0);
                break;
            default:
                printf("Invalid input\n");
                break;
        }
    }
    tree_free(&tree);
    return 0;
}

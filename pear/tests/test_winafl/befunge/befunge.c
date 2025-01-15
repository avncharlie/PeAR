#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINEWIDTH 80
#define PAGEHEIGHT 25

#define STACK_SIZE 64

static char page[LINEWIDTH * PAGEHEIGHT];
#define cur page[y * LINEWIDTH + x]

static long POP(long *stack, unsigned *sp) {
  if (*sp <= 0) {
    return 0;
  }
  (*sp)--;
  long v = stack[*sp];
  return v;
}

static void PUSH(long *stack, unsigned *sp, long v) {
  stack[*sp] = v;
  (*sp)++;
}

static void befunge_parse(FILE *fp) {
  int x = 0, y = 0;
  char tc = ' ';

  memset(page, ' ', LINEWIDTH * PAGEHEIGHT);

  while (!feof(fp)) {
    tc = fgetc(fp);
    if (feof(fp)) {
      break;
    }

    if (tc == '\n') {
      x = 0;
      y++;
      if (y >= PAGEHEIGHT) {
        break;
      }
    } else {
      cur = tc;
      x++;
      if (x >= LINEWIDTH) {
        while (tc != '\n') {
          tc = fgetc(fp);
          if (feof(fp)) {
            y = PAGEHEIGHT;
            break;
          }
        }
        x = 0;
        y++;
        if (y >= PAGEHEIGHT) {
          break;
        }
      }
    }
  }
}

static int befunge_interpreter() {
  int x = 0, y = 0;             // PC x and y
  int dx = 1, dy = 0;           // PC direction
  unsigned sp = 0;              // Stack pointer
  long stack[STACK_SIZE] = {0}; // Stack
  bool stringmode = false;

  while (cur != '@' || stringmode) {
    if (stringmode && (cur != '"')) {
      PUSH(stack, &sp, cur);
    } else if (isdigit((int)cur)) {
      PUSH(stack, &sp, cur - '0');
    } else {
      switch (cur) {
      case '>': { // PC -> right
        dx = 1;
        dy = 0;
      } break;
      case '<': { // PC -> left
        dx = -1;
        dy = 0;
      } break;
      case '^': { // PC -> up
        dx = 0;
        dy = -1;
      } break;
      case 'v': { // PC -> down
        dx = 0;
        dy = 1;
      } break;
      case '|': { // PC->up if <value>, else PC->down
        dx = 0;
        if (POP(stack, &sp)) {
          dy = -1;
        } else {
          dy = 1;
        }
      } break;
      case '_': { // PC->left if <value>, else PC->right
        dy = 0;
        if (POP(stack, &sp)) {
          dx = -1;
        } else {
          dx = 1;
        }
      } break;
      case '+': { // <value1 + value2>
        PUSH(stack, &sp, POP(stack, &sp) + POP(stack, &sp));
      } break;
      case '-': { // <value1 - value2>
        long a = POP(stack, &sp);
        long b = POP(stack, &sp);
        PUSH(stack, &sp, b - a);
      } break;
      case '*': { // <value1 * value2>
        PUSH(stack, &sp, POP(stack, &sp) * POP(stack, &sp));
      } break;
      case '/': { // <value1 / value2>
        long a = POP(stack, &sp);
        long b = POP(stack, &sp);
        if (a == 0) {
          fprintf(stderr, "ERROR: divide-by-zero\n");
          return 1;
        } else {
          PUSH(stack, &sp, b / a);
        }
      } break;
      case '%': { // <value1 mod value2>
        long a = POP(stack, &sp);
        long b = POP(stack, &sp);
        PUSH(stack, &sp, b % a);
      } break;
      case '\\': { // Swap
        long a = POP(stack, &sp);
        long b = POP(stack, &sp);
        PUSH(stack, &sp, a);
        PUSH(stack, &sp, b);
      } break;
      case '.': { // outputs <value> as integer
        printf("%ld", POP(stack, &sp));
      } break;
      case ',': { // outputs <value> as ASCII
        printf("%c", (char)POP(stack, &sp));
      } break;
      case '"': { // toggles 'stringmode'
        stringmode = !stringmode;
      } break;
      case ':': { // Duplicate
        long a = POP(stack, &sp);
        PUSH(stack, &sp, a);
        PUSH(stack, &sp, a);
      } break;
      case '!': { // Negate
        if (POP(stack, &sp)) {
          PUSH(stack, &sp, 0);
        } else {
          PUSH(stack, &sp, 1);
        }
      } break;
      case '`': { // <1 if value1 > value2, 0 otherwise>
        long a = POP(stack, &sp);
        long b = POP(stack, &sp);
        PUSH(stack, &sp, a > b);
      } break;
      case '#': { // 'jumps' PC one farther; skips over next command
        x += dx;
        y += dy;
      } break;
      case '$': { // pops <value> but does nothing
        POP(stack, &sp);
      } break;
      case '?': { // PC -> right? left? up? down? ???
        switch ((rand() / 32) % 4) {
        case 0:
          dx = 1;
          dy = 0;
          break;
        case 1:
          dx = -1;
          dy = 0;
          break;
        case 2:
          dx = 0;
          dy = -1;
          break;
        case 3:
          dx = 0;
          dy = 1;
          break;
        }
      } break;
      case '&': { // <value user entered>
        long b;
        scanf("%ld", &b);
        PUSH(stack, &sp, b);
      } break;
      case '~': { // <character user entered>
        char c = getchar();
        PUSH(stack, &sp, c);
      } break;
      case 'g': { // <value at (x,y)>
        long y = POP(stack, &sp);
        long x = POP(stack, &sp);
        if ((y < PAGEHEIGHT) && (y >= 0) && (x < LINEWIDTH) && (x >= 0)) {
          PUSH(stack, &sp, cur);
        } else {
          fprintf(stderr, "ERROR: `get` instruction out-of-bounds (%ld, %ld)\n",
                  x, y);
          return 1;
        }
      } break;
      case 'p': { // puts <value> at (x,y)
        long y = POP(stack, &sp);
        long x = POP(stack, &sp);
        if ((y < PAGEHEIGHT) && (y >= 0) && (x < LINEWIDTH) && (x >= 0)) {
          cur = POP(stack, &sp);
        } else {
          fprintf(stderr, "ERROR: `put` instruction out-of-bounds (%ld, %ld)\n",
                  x, y);
          return 1;
        }
      } break;
      case ' ': // NOP
      case '\t':
      case '\n':
      case '@':
        break;
      default: {
        fprintf(stderr, "ERROR: Unsupported instruction '%c'\n", cur);
        return 1;
      } break;
      }
    }

    x += dx;
    y += dy;

    if (x < 0) {
      x += LINEWIDTH;
    } else {
      x = x % LINEWIDTH;
    }

    if (y < 0) {
      y += PAGEHEIGHT;
    } else {
      y = y % PAGEHEIGHT;
    }
  }

  return 0;
}

__declspec(dllexport) int read_and_test_file(char *fname) {
  int rc = 0;

  FILE *fp = fopen(fname, "r");
  if (!fp) {
    fprintf(stderr, "error: unable to read input file %s\n", fname);
    return 1;
  }

  // Run the befunge interpreter
  befunge_parse(fp);
  rc = befunge_interpreter();

  // Close the input file stream
  fclose(fp);

  return rc;
}

int main(int argc, char *argv[]) {
  // Check command-line arguments
  if (argc != 2) {
    fprintf(stderr, "usage: %s <INPUT_FILE>\n", argv[0]);
    return 1;
  }

  // Open input file
  read_and_test_file(argv[1]);
}

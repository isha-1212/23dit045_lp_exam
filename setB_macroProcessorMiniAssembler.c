#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 256
#define MAX_MACRO 100
#define MAX_PARAM 20
#define MAX_MDT 1000
#define MAX_SYMBOL 500
#define MAX_CODE_LINES 1000
#define MAX_ISSUES 200

typedef struct
{
    char name[32];
    int mdtStart;
    int paramCount;
    char paramName[MAX_PARAM][32];
} Macro;

typedef struct
{
    char text[MAX_LINE];
} MdtLine;

typedef struct
{
    char name[32];
    int address;
} Symbol;

typedef struct
{
    int address;
    char label[32];
    char opcode[32];
    char operand[128];
} SourceLine;

typedef struct
{
    char mnemonic[16];
    int opcode;
} OpCode;

static Macro mnt[MAX_MACRO];
static MdtLine mdt[MAX_MDT];
static Symbol symtab[MAX_SYMBOL];
static SourceLine srcLines[MAX_CODE_LINES];
static char issues[MAX_ISSUES][256];

static int mntCount = 0;
static int mdtCount = 0;
static int symCount = 0;
static int srcCount = 0;
static int issueCount = 0;

static OpCode optab[] = {
    {"LDA", 0x00},
    {"STA", 0x0C},
    {"ADD", 0x18},
    {"SUB", 0x1C},
    {"MUL", 0x20},
    {"DIV", 0x24},
    {"J", 0x3C},
    {"JLT", 0x38},
    {"JEQ", 0x30},
    {"JGT", 0x34},
    {"COMP", 0x28},
    {"LDX", 0x04},
    {"STX", 0x10},
    {"TIX", 0x2C},
    {"RSUB", 0x4C},
    {"", -1}};

static void addError(const char *text)
{
    if (issueCount < MAX_ISSUES)
    {
        strncpy(issues[issueCount], text, sizeof(issues[issueCount]) - 1);
        issues[issueCount][sizeof(issues[issueCount]) - 1] = '\0';
        issueCount++;
    }
}

static void trim(char *s)
{
    size_t len;
    char *start = s;

    while (*start && isspace((unsigned char)*start))
    {
        start++;
    }

    if (start != s)
    {
        memmove(s, start, strlen(start) + 1);
    }

    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
    {
        s[len - 1] = '\0';
        len--;
    }
}

static int isCommentLine(const char *s)
{
    while (*s && isspace((unsigned char)*s))
    {
        s++;
    }
    return (*s == '\0' || *s == ';' || *s == '#');
}

static int is_number(const char *s)
{
    int i = 0;
    if (s == NULL || s[0] == '\0')
    {
        return 0;
    }
    if (s[0] == '+' || s[0] == '-')
    {
        i = 1;
    }
    if (s[i] == '\0')
    {
        return 0;
    }
    for (; s[i] != '\0'; i++)
    {
        if (!isdigit((unsigned char)s[i]))
        {
            return 0;
        }
    }
    return 1;
}

static int startsWith(const char *text, const char *prefix)
{
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static int findOp(const char *opcode)
{
    int i;
    for (i = 0; optab[i].opcode != -1; i++)
    {
        if (strcmp(optab[i].mnemonic, opcode) == 0)
        {
            return optab[i].opcode;
        }
    }
    return -1;
}

static int isDirective(const char *opcode)
{
    return strcmp(opcode, "START") == 0 || strcmp(opcode, "END") == 0 ||
           strcmp(opcode, "WORD") == 0 || strcmp(opcode, "RESW") == 0 ||
           strcmp(opcode, "RESB") == 0 || strcmp(opcode, "BYTE") == 0;
}

static int findMacro(const char *name)
{
    int i;
    for (i = 0; i < mntCount; i++)
    {
        if (strcmp(mnt[i].name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int findSymbol(const char *name)
{
    int i;
    for (i = 0; i < symCount; i++)
    {
        if (strcmp(symtab[i].name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}

static void parseMacroHeader(const char *line, char *macroName, char params[][32], int *paramCount)
{
    char temp[MAX_LINE];
    char *nameTok;
    char *argList;
    char *argTok;
    int count = 0;

    strcpy(temp, line);
    trim(temp);

    nameTok = strtok(temp, " \t");
    if (nameTok == NULL)
    {
        macroName[0] = '\0';
        *paramCount = 0;
        return;
    }

    strcpy(macroName, nameTok);
    *paramCount = 0;

    argList = strtok(NULL, "");
    if (argList == NULL)
    {
        return;
    }

    trim(argList);
    argTok = strtok(argList, ",");
    while (argTok != NULL && count < MAX_PARAM)
    {
        trim(argTok);
        if (argTok[0] == '&')
        {
            memmove(argTok, argTok + 1, strlen(argTok));
        }
        strcpy(params[count], argTok);
        count++;
        argTok = strtok(NULL, ",");
    }

    *paramCount = count;
}

static void replaceParams(char *line, char params[][32], int paramCount)
{
    char out[MAX_LINE] = "";
    char *p = line;

    while (*p)
    {
        if (*p == '&')
        {
            char token[32] = "";
            int j = 0;
            int foundIndex = -1;
            int i;

            p++;
            while (isalnum((unsigned char)*p) || *p == '_')
            {
                if (j < (int)sizeof(token) - 1)
                {
                    token[j++] = *p;
                }
                p++;
            }
            token[j] = '\0';

            for (i = 0; i < paramCount; i++)
            {
                if (strcmp(token, params[i]) == 0)
                {
                    foundIndex = i;
                    break;
                }
            }

            if (foundIndex >= 0)
            {
                char replacement[16];
                sprintf(replacement, "#%d", foundIndex + 1);
                strncat(out, replacement, sizeof(out) - strlen(out) - 1);
            }
            else
            {
                strncat(out, "&", sizeof(out) - strlen(out) - 1);
                strncat(out, token, sizeof(out) - strlen(out) - 1);
            }
        }
        else
        {
            char ch[2] = {*p, '\0'};
            strncat(out, ch, sizeof(out) - strlen(out) - 1);
            p++;
        }
    }

    strcpy(line, out);
}

static void replaceArgs(char *line, char args[][64], int argCount)
{
    char out[MAX_LINE] = "";
    char *p = line;

    while (*p)
    {
        if (*p == '#')
        {
            int index = 0;
            p++;
            while (isdigit((unsigned char)*p))
            {
                index = index * 10 + (*p - '0');
                p++;
            }
            if (index >= 1 && index <= argCount)
            {
                strncat(out, args[index - 1], sizeof(out) - strlen(out) - 1);
            }
        }
        else
        {
            char ch[2] = {*p, '\0'};
            strncat(out, ch, sizeof(out) - strlen(out) - 1);
            p++;
        }
    }

    strcpy(line, out);
}

static int parseLine(const char *line, char *label, char *opcode, char *operand)
{
    char temp[MAX_LINE];
    char *p1;
    char *p2;
    char *p3;

    label[0] = '\0';
    opcode[0] = '\0';
    operand[0] = '\0';

    strcpy(temp, line);
    trim(temp);
    if (isCommentLine(temp))
    {
        return 0;
    }

    p1 = strtok(temp, " \t");
    p2 = strtok(NULL, " \t");
    p3 = strtok(NULL, "");

    if (p1 == NULL)
    {
        return 0;
    }

    if (p1[strlen(p1) - 1] == ':')
    {
        p1[strlen(p1) - 1] = '\0';
        strcpy(label, p1);

        if (p2 != NULL)
        {
            strcpy(opcode, p2);
        }

        if (p3 != NULL)
        {
            trim(p3);
            strcpy(operand, p3);
        }
    }
    else
    {
        strcpy(opcode, p1);
        if (p2 != NULL)
        {
            strcpy(operand, p2);
            if (p3 != NULL)
            {
                strcat(operand, " ");
                strcat(operand, p3);
            }
        }
    }

    return 1;
}

static void parseCallArgs(const char *argString, char args[][64], int *count)
{
    char temp[128];
    char *tok;
    int n = 0;

    *count = 0;
    if (argString == NULL || argString[0] == '\0')
    {
        return;
    }

    strcpy(temp, argString);
    tok = strtok(temp, ",");
    while (tok != NULL && n < MAX_PARAM)
    {
        trim(tok);
        strcpy(args[n], tok);
        n++;
        tok = strtok(NULL, ",");
    }

    *count = n;
}

static int byteSize(const char *operand)
{
    int len = (int)strlen(operand);
    if (startsWith(operand, "C'") && len >= 3 && operand[len - 1] == '\'')
    {
        return len - 3;
    }
    if (startsWith(operand, "X'") && len >= 3 && operand[len - 1] == '\'')
    {
        return (len - 3 + 1) / 2;
    }
    return 1;
}

static void byteToObj(const char *operand, char *obj)
{
    int i;
    obj[0] = '\0';

    if (startsWith(operand, "C'") && operand[strlen(operand) - 1] == '\'')
    {
        int end = (int)strlen(operand) - 1;
        for (i = 2; i < end; i++)
        {
            char hex[3];
            sprintf(hex, "%02X", (unsigned char)operand[i]);
            strcat(obj, hex);
        }
        return;
    }

    if (startsWith(operand, "X'") && operand[strlen(operand) - 1] == '\'')
    {
        int end = (int)strlen(operand) - 1;
        for (i = 2; i < end; i++)
        {
            if (!isspace((unsigned char)operand[i]))
            {
                char ch[2] = {operand[i], '\0'};
                strcat(obj, ch);
            }
        }
        return;
    }

    sprintf(obj, "%02X", atoi(operand) & 0xFF);
}

static void macroPass(const char *inputFile, const char *expandedFile)
{
    FILE *in = fopen(inputFile, "r");
    FILE *out = fopen(expandedFile, "w");
    char line[MAX_LINE];

    if (in == NULL || out == NULL)
    {
        printf("Error: unable to open input or expanded output file.\n");
        if (in != NULL)
        {
            fclose(in);
        }
        if (out != NULL)
        {
            fclose(out);
        }
        exit(1);
    }

    while (fgets(line, sizeof(line), in) != NULL)
    {
        char clean[MAX_LINE];
        strcpy(clean, line);
        trim(clean);

        if (strcmp(clean, "MACRO") == 0)
        {
            char header[MAX_LINE];
            char macroName[32];
            char params[MAX_PARAM][32];
            int paramCount = 0;

            if (fgets(header, sizeof(header), in) == NULL)
            {
                addError("Malformed macro block: header line missing after MACRO");
                break;
            }

            trim(header);
            parseMacroHeader(header, macroName, params, &paramCount);

            if (macroName[0] == '\0')
            {
                addError("Malformed macro header: macro name is empty");
                continue;
            }

            if (findMacro(macroName) != -1)
            {
                char msg[256];
                sprintf(msg, "Duplicate macro definition: %s", macroName);
                addError(msg);

                while (fgets(line, sizeof(line), in) != NULL)
                {
                    trim(line);
                    if (strcmp(line, "MEND") == 0)
                    {
                        break;
                    }
                }
                continue;
            }

            if (mntCount >= MAX_MACRO)
            {
                addError("MNT is full (too many macros)");
                break;
            }

            strcpy(mnt[mntCount].name, macroName);
            mnt[mntCount].mdtStart = mdtCount;
            mnt[mntCount].paramCount = paramCount;
            for (int i = 0; i < paramCount; i++)
            {
                strcpy(mnt[mntCount].paramName[i], params[i]);
            }
            mntCount++;

            while (fgets(line, sizeof(line), in) != NULL)
            {
                trim(line);
                if (strcmp(line, "MEND") == 0)
                {
                    if (mdtCount < MAX_MDT)
                    {
                        strcpy(mdt[mdtCount].text, "MEND");
                        mdtCount++;
                    }
                    break;
                }

                replaceParams(line, params, paramCount);
                if (mdtCount < MAX_MDT)
                {
                    strcpy(mdt[mdtCount].text, line);
                    mdtCount++;
                }
                else
                {
                    addError("MDT is full (too many macro lines)");
                    break;
                }
            }

            continue;
        }

        if (!isCommentLine(clean))
        {
            char label[32], opcode[32], operand[128];
            if (parseLine(clean, label, opcode, operand))
            {
                int macroIndex = findMacro(opcode);
                if (macroIndex != -1)
                {
                    char args[MAX_PARAM][64];
                    int argCount = 0;
                    int mdtPtr = mnt[macroIndex].mdtStart;

                    parseCallArgs(operand, args, &argCount);
                    if (argCount != mnt[macroIndex].paramCount)
                    {
                        char msg[256];
                        sprintf(msg,
                                "Macro argument mismatch in %s: expected %d, got %d",
                                mnt[macroIndex].name,
                                mnt[macroIndex].paramCount,
                                argCount);
                        addError(msg);
                    }

                    while (mdtPtr < mdtCount && strcmp(mdt[mdtPtr].text, "MEND") != 0)
                    {
                        char expanded[MAX_LINE];
                        strcpy(expanded, mdt[mdtPtr].text);
                        replaceArgs(expanded, args, argCount);
                        fprintf(out, "%s\n", expanded);
                        mdtPtr++;
                    }
                    continue;
                }

                if (findOp(opcode) == -1 && !isDirective(opcode))
                {
                    if (label[0] == '\0')
                    {
                        char msg[256];
                        sprintf(msg, "Undefined macro or invalid opcode: %s", opcode);
                        addError(msg);
                    }
                }
            }
        }

        fprintf(out, "%s", line);
    }

    fclose(in);
    fclose(out);
}

static void pass1(const char *expandedFile, const char *intermediateFile)
{
    FILE *in = fopen(expandedFile, "r");
    FILE *inter = fopen(intermediateFile, "w");
    char line[MAX_LINE];
    int locctr = 0;
    int started = 0;

    if (in == NULL || inter == NULL)
    {
        printf("Error: unable to open pass1 files.\n");
        if (in != NULL)
        {
            fclose(in);
        }
        if (inter != NULL)
        {
            fclose(inter);
        }
        exit(1);
    }

    while (fgets(line, sizeof(line), in) != NULL)
    {
        char clean[MAX_LINE];
        char label[32], opcode[32], operand[128];
        int increment = 0;

        strcpy(clean, line);
        trim(clean);
        if (isCommentLine(clean))
        {
            continue;
        }

        if (!parseLine(clean, label, opcode, operand))
        {
            continue;
        }

        if (strcmp(opcode, "START") == 0 && !started)
        {
            started = 1;
            locctr = is_number(operand) ? atoi(operand) : (int)strtol(operand, NULL, 16);

            if (srcCount < MAX_CODE_LINES)
            {
                srcLines[srcCount].address = locctr;
                strcpy(srcLines[srcCount].label, label);
                strcpy(srcLines[srcCount].opcode, opcode);
                strcpy(srcLines[srcCount].operand, operand);
                srcCount++;
            }
            continue;
        }

        if (!started)
        {
            started = 1;
            locctr = 0;
        }

        if (label[0] != '\0')
        {
            if (findSymbol(label) != -1)
            {
                char msg[256];
                sprintf(msg, "Duplicate label: %s", label);
                addError(msg);
            }
            else if (symCount < MAX_SYMBOL)
            {
                strcpy(symtab[symCount].name, label);
                symtab[symCount].address = locctr;
                symCount++;
            }
            else
            {
                addError("SYMTAB is full");
            }
        }

        if (srcCount < MAX_CODE_LINES)
        {
            srcLines[srcCount].address = locctr;
            strcpy(srcLines[srcCount].label, label);
            strcpy(srcLines[srcCount].opcode, opcode);
            strcpy(srcLines[srcCount].operand, operand);
            srcCount++;
        }

        if (findOp(opcode) != -1)
        {
            increment = 3;
        }
        else if (strcmp(opcode, "WORD") == 0)
        {
            increment = 3;
        }
        else if (strcmp(opcode, "RESW") == 0)
        {
            increment = 3 * atoi(operand);
        }
        else if (strcmp(opcode, "RESB") == 0)
        {
            increment = atoi(operand);
        }
        else if (strcmp(opcode, "BYTE") == 0)
        {
            increment = byteSize(operand);
        }
        else if (strcmp(opcode, "END") == 0)
        {
            increment = 0;
        }
        else
        {
            char msg[256];
            sprintf(msg, "Invalid opcode in pass1: %s", opcode);
            addError(msg);
        }

        locctr += increment;
    }

    for (int i = 0; i < srcCount; i++)
    {
        fprintf(inter, "%04X\t%-10s\t%-10s\t%-20s\n",
                srcLines[i].address,
                srcLines[i].label,
                srcLines[i].opcode,
                srcLines[i].operand);
    }

    fclose(in);
    fclose(inter);
}

static void pass2(const char *machineFile, const char *symtabFile)
{
    FILE *mc = fopen(machineFile, "w");
    FILE *st = fopen(symtabFile, "w");

    if (mc == NULL || st == NULL)
    {
        printf("Error: unable to open pass2 output files.\n");
        if (mc != NULL)
        {
            fclose(mc);
        }
        if (st != NULL)
        {
            fclose(st);
        }
        exit(1);
    }

    fprintf(st, "SYMBOL\tADDRESS\n");
    for (int i = 0; i < symCount; i++)
    {
        fprintf(st, "%-10s\t%04X\n", symtab[i].name, symtab[i].address);
    }

    fprintf(mc, "ADDR\tLABEL\tOPCODE\tOPERAND\tOBJECT_CODE\n");
    for (int i = 0; i < srcCount; i++)
    {
        char obj[128] = "-";
        int op = findOp(srcLines[i].opcode);

        if (op != -1)
        {
            int targetAddress = 0;

            if (srcLines[i].operand[0] == '\0')
            {
                targetAddress = 0;
            }
            else if (is_number(srcLines[i].operand))
            {
                targetAddress = atoi(srcLines[i].operand);
            }
            else
            {
                int symIndex = findSymbol(srcLines[i].operand);
                if (symIndex == -1)
                {
                    char msg[256];
                    sprintf(msg, "Undefined symbol: %s", srcLines[i].operand);
                    addError(msg);
                    targetAddress = 0;
                }
                else
                {
                    targetAddress = symtab[symIndex].address;
                }
            }

            sprintf(obj, "%02X%04X", op & 0xFF, targetAddress & 0xFFFF);
        }
        else if (strcmp(srcLines[i].opcode, "WORD") == 0)
        {
            int value = is_number(srcLines[i].operand) ? atoi(srcLines[i].operand) : 0;
            sprintf(obj, "%06X", value & 0xFFFFFF);
        }
        else if (strcmp(srcLines[i].opcode, "BYTE") == 0)
        {
            byteToObj(srcLines[i].operand, obj);
        }
        else if (strcmp(srcLines[i].opcode, "RESW") == 0 ||
                 strcmp(srcLines[i].opcode, "RESB") == 0 ||
                 strcmp(srcLines[i].opcode, "START") == 0 ||
                 strcmp(srcLines[i].opcode, "END") == 0)
        {
            strcpy(obj, "-");
        }

        fprintf(mc, "%04X\t%s\t%s\t%s\t%s\n",
                srcLines[i].address,
                srcLines[i].label,
                srcLines[i].opcode,
                srcLines[i].operand,
                obj);
    }

    fclose(mc);
    fclose(st);
}

static void printTables(void)
{
    int i, j;

    printf("\nMNT\n");
    printf("************\n");
    printf("Idx\tName\tMDTStart\tParams\n");
    for (i = 0; i < mntCount; i++)
    {
        printf("%d\t%s\t%d\t\t%d\n", i, mnt[i].name, mnt[i].mdtStart, mnt[i].paramCount);
    }

    printf("\nMDT\n");
    printf("************\n");
    for (i = 0; i < mdtCount; i++)
    {
        printf("%d\t%s\n", i, mdt[i].text);
    }

    printf("\nALA\n");
    printf("************\n");
    for (i = 0; i < mntCount; i++)
    {
        printf("Macro: %s\n", mnt[i].name);
        for (j = 0; j < mnt[i].paramCount; j++)
        {
            printf("  #%d -> &%s\n", j + 1, mnt[i].paramName[j]);
        }
    }
}

static void printErrors(void)
{
    int i;
    if (issueCount == 0)
    {
        printf("\nNo errors!!\n");
        return;
    }

    printf("\nNo errors!! (%d):\n", issueCount);
    for (i = 0; i < issueCount; i++)
    {
        printf("%d. %s\n", i + 1, issues[i]);
    }
}

int main(int argc, char *argv[])
{
    const char *inputFile;
    const char *expandedFile = "expandedCode.asm";
    const char *intermediateFile = "intermediateCode.txt";
    const char *symtabFile = "symbolTable.txt";
    const char *machineFile = "machineCode.txt";

    if (argc < 2)
    {
        printf("Usage: %s <input_file.asm>\n", argv[0]);
        return 1;
    }

    inputFile = argv[1];

    macroPass(inputFile, expandedFile);
    pass1(expandedFile, intermediateFile);
    pass2(machineFile, symtabFile);

    printTables();
    printErrors();

    printf("\nGenerated files:\n");
    printf("1) %s\n", expandedFile);
    printf("2) %s\n", intermediateFile);
    printf("3) %s\n", symtabFile);
    printf("4) %s\n", machineFile);

    return 0;
}

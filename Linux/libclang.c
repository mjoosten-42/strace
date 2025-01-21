#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SIZEOF(x) (sizeof(x) / sizeof(*x))

typedef enum {
	ARCH_I386,
	ARCH_COMMON,
	ARCH_64,
	ARCH_X32,
} e_arch;

typedef struct {
	int nr;
	e_arch arch;
	char name[30];
	char entry[35];
} info;

typedef struct s_data {
	int current;
	const info *i;
}	t_data;


enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
const char *get_format(CXType type);
void print_type(CXType type, CXClientData clientdata);

int main(int argc, char **argv) {
	t_data data = { 0, NULL };

	const char *file = "syscalls.h";

	const info array[] = {
#include "table.h"
	};
	const size_t size = SIZEOF(array);

	if (argc > 1) {
		file = argv[1];
	}

	CXIndex index = clang_createIndex(0, 0);
	CXTranslationUnit unit = clang_parseTranslationUnit(index, file, NULL, 0, NULL, 0, CXTranslationUnit_None | CXTranslationUnit_IncludeBriefCommentsInCodeCompletion);

	if (unit == NULL) {
		fprintf(stderr, "Unable to parse translation unit. Quitting.\n");
		return 1;
	}

	for (size_t i = 0; i < size; i++) {
		CXCursor cursor = clang_getTranslationUnitCursor(unit);
	
		if (!strcmp(array[i].name, "mmap")) {
			(void)2;
		}

		data.i = &array[i];
		clang_visitChildren(cursor, prototype_visitor, &data);
	}
}

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	enum CXCursorKind kind = clang_getCursorKind(cursor);

	if (kind != CXCursor_FunctionDecl) {
		return CXChildVisit_Continue;
	}

	CXString spelling = clang_getCursorSpelling(cursor);

	if (strcmp(clang_getCString(spelling), data->i->entry)) {
		return CXChildVisit_Continue;
	}

	CXString display = clang_getCursorDisplayName(cursor);
	CXType proto = clang_getCursorType(cursor);
	int argc = clang_Cursor_getNumArguments(cursor);

	//printf("\t\t/* %s */\n", clang_getCString(display));	// prototype

	// general info
	printf("\t\t{ ");
	printf("%-6s, ", data->i->arch == ARCH_I386 ? "X86" : "X86_64");
	printf("%3i, ", data->i->nr);							// syscall number
	printf("%i, ", argc);									// argc
	printf("\"%s\", ", data->i->name);			// syscall name
	
	// return type
	CXType return_type = clang_getResultType(proto);
	int size = clang_Type_getSizeOf(return_type);
	const char *format = get_format(return_type);

	printf("{ \"%s\", %i }, ", format, size);				// format
	printf("{ ");

	for (int i = 0; i < argc; i++) {
		CXType arg = clang_getArgType(proto, i);
		const char *format = get_format(arg);			
		int size = clang_Type_getSizeOf(arg);

		if (size == CXTypeLayoutError_Incomplete) {
			size = sizeof(void *);
		}

		printf("{ \"%s\", %i }", format, size);				// format

		if (i < argc - 1) {
			printf(",");
		}
		
		printf(" ");
	}

	printf("} },\n");
	
	data->current++;

	clang_disposeString(display);
	clang_disposeString(spelling);

	return CXChildVisit_Continue;
}

const char *get_format(CXType type) {
	CXType pointee;
	const static char *formats[] = {
		"%lu",	// ULong
		"%li",	// Long
		"%u",	// UInt
		"%i",	// Int
		"%p",	// Pointer
		"%d",	// Enum
		"%p",	// ConstantArray
		"\\\"%s\\\"",	// Pointer Char
	};

	type = clang_getCanonicalType(type);

	switch (type.kind) {
		case CXType_ULong:
			return formats[0];
		case CXType_Long:
			return formats[1];
		case CXType_UInt:
			return formats[2];
		case CXType_Int:
			return formats[3];
		case CXType_Pointer:
		case CXType_IncompleteArray:
			return formats[4];
		case CXType_Enum:
			return formats[5];
		case CXType_ConstantArray:
			return formats[6];
		default:
			return formats[3];
	};
}

void print_type(CXType type, CXClientData clientdata) {
	t_data *data = (t_data *)clientdata;
	CXType pointee;
	
	type = clang_getCanonicalType(type);

	printf("%s", clang_getCString(clang_getTypeKindSpelling(type.kind)));

	switch (type.kind) {
		case CXType_Pointer:
			pointee = clang_getPointeeType(type);
			
			printf(" ");
			print_type(pointee, clientdata);
			break;
		case CXType_ConstantArray:
		case CXType_IncompleteArray:
			printf(" ");
			print_type(clang_getArrayElementType(type), clientdata);
			break;
		case CXType_Record:
			if (clang_Type_getSizeOf(type) == -2) {
				printf(" { /* Dependent */ }");
				break;
			} 

			//clang_Type_visitFields(type, field_visitor, clientdata);
		default:
			break;
	}
}


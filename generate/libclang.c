#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

typedef struct s_data {
	int current;
	int inspect;
}	t_data;

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
const char *get_format(CXType type);
void print_type(CXType type, CXClientData clientdata);



int main(int argc, char **argv) {
	t_data data = { 0, -1 };
	const char *file = "../inc/prototypes.h";

	if (argc > 1) {
		file = argv[1];
	}

	if (argc > 2 && isdigit(*argv[2])) {
		data.inspect = atoi(argv[2]);
	}

	CXIndex index = clang_createIndex(0, 0);
	CXTranslationUnit unit = clang_parseTranslationUnit(index, file, NULL, 0, NULL, 0, CXTranslationUnit_None | CXTranslationUnit_IncludeBriefCommentsInCodeCompletion);

	if (unit == NULL) {
		fprintf(stderr, "Unable to parse translation unit. Quitting.\n");
		return 1;
	}

	CXCursor cursor = clang_getTranslationUnitCursor(unit);
	
	printf("#include \"syscall.h\"\n");
	printf("\n");
	printf("const t_syscall_prototype *syscall_get_prototype(int nr) {\n");
	printf("\tstatic const t_syscall_prototype syscalls[] = {\n");

	clang_visitChildren(cursor, prototype_visitor, &data);

	printf("\t};\n");
	printf("\n");
	printf("\treturn &syscalls[nr];\n");
	printf("}\n");

	printf("\n");
	printf("static const size_t syscall_max = %d;\n", data.current);
}

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	int number = atoi(clang_getCString(clang_Cursor_getBriefCommentText(cursor)));

	// fill non-continuous syscall entries
	for (; data->current < number; data->current++) {
		printf("\t\t{ 0 },\n");
	}

	if (data->inspect == -1 || data->inspect == number) {
		CXString spelling = clang_getCursorSpelling(cursor);
		CXString display = clang_getCursorDisplayName(cursor);
		CXType proto = clang_getCursorType(cursor);
		int argc = clang_Cursor_getNumArguments(cursor);

		printf("\t\t/* %s */\n", clang_getCString(display));	// prototype

		// general info
		printf("\t\t{ ");
		printf("%3i, ", data->current);							// syscall number
		printf("%i, ", argc);									// argc
		printf("\"%s\", ", clang_getCString(spelling));			// syscall name
		
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
	} else {
		printf("\t\t{ 0 },\n");

		data->current++;
	}

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
		"%s",	// Pointer Char
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
			pointee = clang_getPointeeType(type);

			switch (pointee.kind) {
				case CXType_Char_S:
					return formats[7];
				default:
					return formats[4];
			};
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


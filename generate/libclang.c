#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SIZE 64

typedef struct s_data {
	int current;
	int inspect;
}	t_data;

const char *file = "generate/prototypes.h";

enum CXChildVisitResult prototype(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult argument(CXCursor cursor, CXCursor parent, CXClientData clientdata);

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult argument_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXVisitorResult field_visitor(CXCursor cursor, CXClientData clientdata);
void print_argument(CXCursor cursor, CXType type, CXClientData clientdata);
void print_type(CXType type, CXClientData clientdata);
const char *getTypeSpelling(CXType type);

int main(int argc, char **argv) {
	t_data data = { 0, -1 };
	CXIndex index = clang_createIndex(0, 0);
	CXTranslationUnit unit = clang_parseTranslationUnit(index, file, NULL, 0, NULL, 0, CXTranslationUnit_None | CXTranslationUnit_IncludeBriefCommentsInCodeCompletion);

	if (unit == NULL) {
		fprintf(stderr, "Unable to parse translation unit. Quitting.\n");
		return 1;
	}

	CXCursor cursor = clang_getTranslationUnitCursor(unit);
	
	if (argc >= 2 && isdigit(*argv[1])) {
		data.inspect = atoi(argv[1]);
	}

	printf("#include \"syscall.h\"\n");
	printf("\n");
	printf("const syscall_info *get_syscall_info(int nr) {\n");
	printf("\tstatic const syscall_info syscalls[] = {\n");

	clang_visitChildren(cursor, prototype_visitor, &data);

	printf("\t};\n");
	printf("\n");
	printf("\treturn &syscalls[nr];\n");
	printf("}\n");
}

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	int number = atoi(clang_getCString(clang_Cursor_getBriefCommentText(cursor)));

	while (data->current < number) {
		printf("\t\t{ %i },\n", data->current);

		data->current++;
	}

	if (data->inspect == -1 || data->inspect == number) {
		CXType proto = clang_getCursorType(cursor);
		CXType return_type = clang_getResultType(proto);
		int argc = clang_Cursor_getNumArguments(cursor);
		CXString spelling = clang_getCursorSpelling(cursor);

		//TODO: args
		printf("\t\t{ %i, %i, %s },\n", data->current, argc, clang_getCString(spelling));

		data->current++;
	}

	return CXChildVisit_Continue;
}

enum CXChildVisitResult argument_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXType type = clang_getCursorType(cursor);
	enum CXCursorKind cursorKind = clang_getCursorKind(cursor);

	if (cursorKind == CXCursor_ParmDecl) {
		print_argument(cursor, type, clientdata);
	}

	return CXChildVisit_Continue;
}

enum CXVisitorResult field_visitor(CXCursor cursor, CXClientData clientdata) {
	CXType type = clang_getCanonicalType(clang_getCursorType(cursor));
	t_data *data = (t_data *)clientdata;

	print_type(type, clientdata);

	return CXVisit_Continue;
}

void print_argument(CXCursor cursor, CXType type, CXClientData clientdata) {
	type = clang_getCanonicalType(type);
	int size = clang_Type_getSizeOf(type);
	t_data *data = (t_data *)clientdata;

	// CXType_IncompleteArray decays to pointer
	if (size == CXTypeLayoutError_Incomplete) {
		size = sizeof(void *);
	}

	printf("\t%d: ", size);
	print_type(type, clientdata);
	printf("\n");
}

void print_type(CXType type, CXClientData clientdata) {
	t_data *data = (t_data *)clientdata;
	CXType pointee;
	
	type = clang_getCanonicalType(type);

	printf("%s", getTypeSpelling(type));

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

			clang_Type_visitFields(type, field_visitor, clientdata);
		default:
			break;
	}
}

const char *getTypeSpelling(CXType type) {
	return clang_getCString(clang_getTypeKindSpelling(type.kind));
}

const char *indents(int level) {
	static char tabs[SIZE] = { 0 };

	memset(tabs, '\t', SIZE - 1);

	return tabs + SIZE - 1 - level;
}


#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define SIZE 64

typedef struct s_data {
	int nr;
	int inspect;
	int type_exists[200];
	int indent;
	CXType last_record_type;
}	t_data;

const char *file = "generate/prototypes.c";

enum CXChildVisitResult prototype(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult argument(CXCursor cursor, CXCursor parent, CXClientData clientdata);

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult argument_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXVisitorResult field_visitor(CXCursor cursor, CXClientData clientdata);
void print_argument(CXCursor cursor, CXType type, CXClientData clientdata);
void print_type(CXType type, CXClientData clientdata);
const char *getTypeSpelling(CXType type);
const char *indents(int level);

int main(int argc, char **argv) {
	t_data data = { 0, -1, { 0 }, 0, CXType_Invalid };
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

	clang_visitChildren(cursor, prototype_visitor, &data);
}

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	if (data->inspect == -1 || data->inspect == data->nr) {
		CXString display_name = clang_getCursorDisplayName(cursor);
		CXType type = clang_getCursorType(cursor);
		CXType return_type = clang_getResultType(type);
		int argc = clang_Cursor_getNumArguments(cursor);

		data->indent++;

		int number = atoi(clang_getCString(clang_Cursor_getBriefCommentText(cursor)));

		print_argument(cursor, return_type, clientdata);
		printf("%3i: %s\n", number, clang_getCString(display_name));
		clang_visitChildren(cursor, argument_visitor, clientdata);
		printf("\n");
		data->indent--;
	}

	data->nr++;

	if (data->type_exists[CXType_Invalid]) {
		return CXChildVisit_Break;
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

	if (type.kind == CXType_Pointer && clang_equalTypes(clang_getPointeeType(type), data->last_record_type)) {
		printf("/ *Recursive type */");
	} else {
		print_type(type, clientdata);
		printf(",\n%s", indents(data->indent));
	}

	return CXVisit_Continue;
}

void print_argument(CXCursor cursor, CXType type, CXClientData clientdata) {
	type = clang_getCanonicalType(type);
	int size = clang_Type_getSizeOf(type);
	t_data *data = (t_data *)clientdata;

	data->type_exists[type.kind] = 1;

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

			data->last_record_type = type;
			data->indent++;
			printf(" {\n%s", indents(data->indent));
			int ret = clang_Type_visitFields(type, field_visitor, clientdata);
			data->indent--;
			printf("\r%s}", indents(data->indent));
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


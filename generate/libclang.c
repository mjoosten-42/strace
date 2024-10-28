#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>

typedef struct s_data {
	int nr;
	int inspect;
	int type_exists[200];
}	t_data;

const char *file = "generate/prototypes.c";

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult argument_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
void print_argument(CXType type, CXClientData clientdata);
const char *getTypeSpelling(CXType type);

int main() {
	t_data data = { 0, 22, { 0 } };
	CXIndex index = clang_createIndex(0, 0);
	CXTranslationUnit unit = clang_parseTranslationUnit(index, file, NULL, 0, NULL, 0, CXTranslationUnit_None);

	if (unit == NULL) {
		fprintf(stderr, "Unable to parse translation unit. Quitting.\n");
		return 1;
	}

	CXCursor cursor = clang_getTranslationUnitCursor(unit);

	clang_visitChildren(cursor, prototype_visitor, &data);

	printf("\n");

	for (int i = 0; i < 200; i++) {
		if (data.type_exists[i]) {
			CXString spelling = clang_getTypeKindSpelling(i);
		
			printf("%s\n", clang_getCString(spelling));
		}
	}
}

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	if (data->inspect == -1 || data->nr == data->inspect) {
		CXString display_name = clang_getCursorDisplayName(cursor);
		CXType type = clang_getCursorType(cursor);
		CXType return_type = clang_getResultType(type);

		print_argument(return_type, clientdata);
		printf("%3i: %s\n", data->nr, (char *)display_name.data);
		clang_visitChildren(cursor, argument_visitor, clientdata);
		printf("\n");
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
		print_argument(type, clientdata);
	}

	return CXChildVisit_Continue;
}

void print_argument(CXType type, CXClientData clientdata) {
	type = clang_getCanonicalType(type);
	int size = clang_Type_getSizeOf(type);
	t_data *data = (t_data *)clientdata;

	data->type_exists[type.kind] = 1;

	printf("\t%d: %s", size, getTypeSpelling(type));

	if (type.kind == CXType_Pointer) {
		printf(" %s", getTypeSpelling(clang_getPointeeType(type)));
	}

	printf("\n");
}

const char *getTypeSpelling(CXType type) {
	return clang_getCString(clang_getTypeKindSpelling(type.kind));
}


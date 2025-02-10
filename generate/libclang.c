#include <clang-c/Index.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

typedef struct s_data {
	int current;
	const char *to_inspect;
}	t_data;

enum CXChildVisitResult prototype_visitor(CXCursor cursor, CXCursor parent, CXClientData clientdata);
enum CXChildVisitResult counter(CXCursor cursor, CXCursor parent, CXClientData clientdata);

int main(int argc, char **argv) {
	const char *file = NULL;
	int count_flag = 0;
	t_data data = { 0 };

	for (int c = 0; c != -1; c = getopt(argc, argv, "ch:i:")) {
		switch (c) {
			case 'c':
				count_flag = 1;
				break;
			case 'h':
				file = optarg;
				break;
			case 'i':
				data.to_inspect = optarg;
				break;
			default:
				break;
		};
	}

	if (!file || !*file) {
		eprintf("usage: %s: -h HEADER [-i SYSCALL NAME] [-c]\n", basename(argv[0]));
		return 1;
	}

	CXIndex index = clang_createIndex(0, 0);
	CXTranslationUnit unit = clang_parseTranslationUnit(index, file, NULL, 0, NULL, 0, CXTranslationUnit_None | CXTranslationUnit_IncludeBriefCommentsInCodeCompletion);

	if (unit == NULL) {
		eprintf("Unable to parse translation unit. Quitting.\n");
		return 1;
	}

	CXCursor cursor = clang_getTranslationUnitCursor(unit);

	if (count_flag) {
		clang_visitChildren(cursor, counter, &data);

		printf("%d\n", data.current);
	} else {
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

	CXString spelling = clang_getCursorSpelling(cursor);
	
	if (data->to_inspect && strcmp(data->to_inspect, clang_getCString(spelling))) {
		clang_disposeString(spelling);
		return CXChildVisit_Continue;
	}

	CXString display = clang_getCursorDisplayName(cursor);
	CXType proto = clang_getCursorType(cursor);
	int number = atoi(clang_getCString(clang_Cursor_getBriefCommentText(cursor)));
	int argc = clang_Cursor_getNumArguments(cursor);

	while (data->current < number) {
		printf("\t\t{ },\n");
		data->current++;
	}

	printf("\t\t{ ");
	// general info
	//printf("%3i, ", data->current);							// syscall number
	printf("\"%s\", ", clang_getCString(spelling));				// syscall name
	printf("%i, ", argc);										// argc
	
	// return type
	CXType return_type = clang_getResultType(proto);
	CXString return_spelling = clang_getTypeKindSpelling(return_type.kind);
	int size = clang_Type_getSizeOf(return_type);

	printf("{ %s, %i }, ", clang_getCString(return_spelling), size);	// return
	printf("{ ");

	for (int i = 0; i < argc; i++) {
		CXType arg = clang_getCanonicalType(clang_getArgType(proto, i));
		CXString arg_spelling = clang_getTypeKindSpelling(arg.kind);
		int size = clang_Type_getSizeOf(arg);

		if (size == CXTypeLayoutError_Incomplete) {
			size = sizeof(void *);
		}

		printf("{ %s, %i }", clang_getCString(arg_spelling), size);				// format

		if (i < argc - 1) {
			printf(",");
		}
		
		printf(" ");

		clang_disposeString(arg_spelling);
	}

	printf("} },\n");
	
	// x86 syscall called break is skipped because it's a keyword
	if (number == 16 && !strcmp(clang_getCString(spelling), "lchown")) {
		printf("\t\t{ \"break\", 0, { Long, 8 }, { } },\n");
		data->current++;
	}
	
	data->current++;
	
	clang_disposeString(display);
	clang_disposeString(spelling);
	clang_disposeString(return_spelling);

	return CXChildVisit_Continue;
}

enum CXChildVisitResult counter(CXCursor cursor, CXCursor parent, CXClientData clientdata) {
	CXSourceLocation location = clang_getCursorLocation(cursor);
	t_data *data = (t_data *)clientdata;

	// Ignore includes
	if (!clang_Location_isFromMainFile(location)) {
		return CXChildVisit_Continue;
	}

	int number = atoi(clang_getCString(clang_Cursor_getBriefCommentText(cursor)));

	while (data->current < number) {
		data->current++;
	}

	data->current++;

	return CXChildVisit_Continue;
}


#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <yajl/yajl_tree.h>

static unsigned char jdata[1000000];

int main(void)
{
	size_t rd;
	yajl_val node;
	jdata[0] = 0;

	rd = fread((void *)jdata, 1, sizeof(jdata) - 1, stdin);
	if(rd == 0 && !feof(stdin))
		return 1;

	if(rd >= sizeof(jdata) - 1)
		return 1;

	node = yajl_tree_parse((const char *)jdata, NULL, 0);
	if(node == NULL)
		return 1;

	static const char *root[] = { NULL, 0 };
	static const char *r_name[] = { "name", 0 };
	static const char *r_sever[] = { "severity", 0 };
	static const char *r_status[] = { "status", 0 };
	static const char *r_version[] = { "affected", 0 };
	static const char *r_pkgs[] = { "packages", 0 };

	char *status = NULL;
	char *version = NULL;
	char *name = NULL;
	char *sever = NULL;
	char *package = NULL;

	yajl_val data = yajl_tree_get(node, root, yajl_t_array);
	if(!data || !YAJL_IS_ARRAY(data)){
		yajl_tree_free(node);
		return 0;
	}

	char installed[10000][512];
	DIR *dir = opendir("/var/lib/pacman/local/");
	struct dirent *ep;
	int x=0;

	if(dir != NULL){
		while((ep = readdir(dir))){
			char filen[512];
			char line[512];
			snprintf(filen, sizeof filen, "/var/lib/pacman/local/%s/desc", ep->d_name);
			FILE *file = fopen(filen, "r");
			int count = 0;

			if(file == NULL) continue;

			while(fgets(line, sizeof line, file) != NULL){
				if(count++ == 1){
					line[strcspn(line, "\n")] = 0;
					strcpy(installed[x], line);
					x++;
					break;
				}
			}
			fclose(file);
		}
		closedir(dir);
	}

	int xlen = sizeof(installed)/sizeof(installed[0]);
	int i, j, k;

	printf("PACKAGES,AFFECTED,STATUS,SEVERITY,NAME\n");

	for(i=0; i < data->u.array.len; i++){
		yajl_val obj = data->u.array.values[i];
		yajl_val d_pkgs = yajl_tree_get(obj, r_pkgs, yajl_t_array);

		bool isinstalled = false;

		if(d_pkgs && YAJL_IS_ARRAY(d_pkgs)){
			for(j=0; j < d_pkgs->u.array.len; j++){
				yajl_val pkgobj = d_pkgs->u.array.values[j];
				if(pkgobj) package = YAJL_GET_STRING(pkgobj);
				for(k=0; k < xlen; k++)
					if(strcmp(installed[k], package) == 0) isinstalled = true;
			}
		}

		if(!isinstalled) continue;

		yajl_val statusobj = yajl_tree_get(obj, r_status, yajl_t_string);
		if(statusobj) status = YAJL_GET_STRING(statusobj);
		if(strcmp(status, "Vulnerable") != 0) continue;

		yajl_val versobj = yajl_tree_get(obj, r_version, yajl_t_string);
		yajl_val nameobj = yajl_tree_get(obj, r_name, yajl_t_string);
		yajl_val severobj = yajl_tree_get(obj, r_sever, yajl_t_string);

		if(versobj) version = YAJL_GET_STRING(versobj);
		if(nameobj) name = YAJL_GET_STRING(nameobj);
		if(severobj) sever = YAJL_GET_STRING(severobj);

		printf("%s,%s,%s,%s,%s\n", package, version, status, sever, name);
	}
	
	yajl_tree_free(node);
	return 0;
}

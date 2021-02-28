#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <yajl/yajl_tree.h>
#include <curl/curl.h>

static int32_t comp(const void *a, const void *b)
{
	return strcmp(*(const char**)a, *(const char**)b);
}

static void sort(char *arr[], uint_fast16_t n)
{
	qsort(arr, n, sizeof(const char*), comp);
}

static bool binsearch(char *str[], int_fast16_t max, char *value)
{
	int_fast16_t begin = 0;
	int_fast16_t end = max - 1;

	while(begin <= end){
		int_fast16_t cond = 0;
		int_fast16_t position = (begin + end) / 2;
		if((cond = strcmp(str[position], value)) == 0)
			return true;
		if(cond < 0)
			begin = position + 1;
		else
			end = position - 1;
	}

	return false;
}

struct memstruct {
	char *memory;
	int_fast16_t size;
};

static int_fast16_t curlcb(void *contents, int_fast16_t size, int_fast16_t nmemb, void *userp)
{
	int_fast16_t realsize = size * nmemb;
	struct memstruct *mem = (struct memstruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if(ptr == NULL){
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

int main(void)
{
	CURL *curl_handle;
	CURLcode res;
	struct memstruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, "https://security.archlinux.org/issues/vulnerable/json");
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curlcb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	res = curl_easy_perform(curl_handle);

	if(res != CURLE_OK){
		curl_easy_cleanup(curl_handle);
		free(chunk.memory);
		curl_global_cleanup();
		return 1;
	}

	char jdata[chunk.size];
	snprintf(jdata, chunk.size + 1, "%s", chunk.memory);

	curl_easy_cleanup(curl_handle);
	free(chunk.memory);
	curl_global_cleanup();

	yajl_val node = yajl_tree_parse(jdata, NULL, 0);
	if(node == NULL)
		return 1;

	static const char *root[] = { NULL, 0 };
	static const char *r_name[] = { "name", 0 };
	static const char *r_sever[] = { "severity", 0 };
	static const char *r_status[] = { "status", 0 };
	static const char *r_version[] = { "affected", 0 };
	static const char *r_pkgs[] = { "packages", 0 };

	yajl_val data = yajl_tree_get(node, root, yajl_t_array);
	if(!data || !YAJL_IS_ARRAY(data)){
		yajl_tree_free(node);
		return 0;
	}

	char *status = NULL;
	char *version = NULL;
	char *name = NULL;
	char *sever = NULL;
	char *package = NULL;
	char *installed[10000];
	char filen[512];
	char line[64];
	uint_fast16_t xlen = 0;
	FILE *file = NULL;
	DIR *dir = opendir("/var/lib/pacman/local/");
	struct dirent *ep;

	if(dir == NULL){
		yajl_tree_free(node);
		return 1;
	}

	while((ep = readdir(dir))){
		snprintf(filen, sizeof(filen), "/var/lib/pacman/local/%s/desc", ep->d_name);
		file = fopen(filen, "r");

		if(file == NULL)
			continue;

		uint_fast16_t count = 0;
		while(fgets(line, sizeof(line), file) != NULL){
			if(count++ == 1){
				line[strlen(line)-1] = 0;
				installed[xlen++] = strdup(line);
				break;
			}
		}
		fclose(file);
	}

	closedir(dir);
	sort(installed, xlen);
	printf("PACKAGES,AFFECTED,STATUS,SEVERITY,NAME\n");

	for(uint_fast16_t i=0; i < data->u.array.len; i++){
		yajl_val obj = data->u.array.values[i];
		yajl_val d_pkgs = yajl_tree_get(obj, r_pkgs, yajl_t_array);

		bool isinstalled = false;

		if(!d_pkgs || !YAJL_IS_ARRAY(d_pkgs))
			continue;

		for(uint_fast16_t j=0; j < d_pkgs->u.array.len; j++){
			yajl_val pkgobj = d_pkgs->u.array.values[j];
			if(pkgobj)
				package = YAJL_GET_STRING(pkgobj);
			if((isinstalled = binsearch(installed, xlen, package)) != 0)
				break;
		}

		if(!isinstalled)
			continue;

		yajl_val statusobj = yajl_tree_get(obj, r_status, yajl_t_string);

		if(statusobj)
			status = YAJL_GET_STRING(statusobj);
		if(strcmp(status, "Vulnerable") != 0)
			continue;

		yajl_val versobj = yajl_tree_get(obj, r_version, yajl_t_string);
		yajl_val nameobj = yajl_tree_get(obj, r_name, yajl_t_string);
		yajl_val severobj = yajl_tree_get(obj, r_sever, yajl_t_string);

		if(versobj)
			version = YAJL_GET_STRING(versobj);
		if(nameobj)
			name = YAJL_GET_STRING(nameobj);
		if(severobj)
			sever = YAJL_GET_STRING(severobj);

		printf("%s,%s,%s,%s,%s\n", package, version, status, sever, name);
	}

	yajl_tree_free(node);
	return 0;
}

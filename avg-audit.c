#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <alpm_octopi_utils.h>
#include <yajl/yajl_tree.h>
#include <curl/curl.h>

#define RED "\x1b[31m"
#define GRN "\x1b[32m"
#define YEL "\x1b[33m"
#define ESC "\x1b[0m"

static bool binsearch(const char *str[], const int_fast16_t max, const char *value)
{
	int_fast16_t begin = 0;
	int_fast16_t end = max - 1;
	
	while(begin <= end){
		int_fast16_t position = (begin + end) / 2;
		int_fast16_t cond = 0;
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

static int_fast16_t curlcb(const void *contents, const int_fast16_t size, const int_fast16_t nmemb, const void *userp)
{
	int_fast16_t realsize = size * nmemb;
	struct memstruct *mem = (struct memstruct *)userp;
	
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if(ptr == NULL)
		return 0;
	
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	
	return realsize;
}

int main(int argc, char *argv[])
{
	bool link = false;
	bool color = false;
	bool printall = false;
	bool printcount = true;
	char *testurl = "https://security.archlinux.org/issues/vulnerable/json";
	
	for(int_fast16_t opt=1; opt < argc && argv[opt][0] == '-'; opt++){
		switch(argv[opt][1]){
			case 'l': link = true; break;
			case 'c': color = true; break;
			case 'a': printall = true; break;
			case 'n': printcount = false; break;
			case 't': testurl = "https://security.archlinux.org/all.json"; break;
			default: fprintf(stderr, "Usage: %s [-alcnt]\n", argv[0]); return 0;
		}
	}
	
	CURL *curl_handle = NULL;
	CURLcode res = 0;
	struct memstruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, testurl);
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
	static const char *r_type[] = { "type", 0 };
	static const char *r_fixed[] = { "fixed", 0 };
	static const char *r_ticket[] = { "ticket", 0 };
	static const char *r_issues[] = { "issues", 0 };
	
	yajl_val data = yajl_tree_get(node, root, yajl_t_array);
	if(!data || !YAJL_IS_ARRAY(data)){
		yajl_tree_free(node);
		return 0;
	}
	
	const char *installed[10000];
	char *COLSEVER = ESC;
	char *COLSTAT = GRN;
	uint_fast16_t xlen = 0;
	uint_fast16_t vulncount = 0;
	AlpmUtils *alpm_utils = alpm_utils_new("/etc/pacman.conf");
	alpm_list_t *pkglist = alpm_utils_get_installed_pkgs(alpm_utils);
	alpm_list_t *p = NULL;
	
	for(p=pkglist; p; p=alpm_list_next(p))
		installed[xlen++] = alpm_pkg_get_name(p->data);
	
	if(printall)
		printf("%-20s%-20s%-12s%-12s%-30s%-12s%-12s%-20s%-12s\n", "PACKAGES","AFFECTED","STATUS","SEVERITY","TYPE","FIXED","TICKET","ISSUE","NAME");
	else
		printf("%-20s%-20s%-12s%-12s%-12s\n", "PACKAGES","AFFECTED","STATUS","SEVERITY","NAME");
	
	for(uint_fast16_t i=0; i < data->u.array.len; i++){
		char *status = "null";
		char *version = "null";
		char *name = "null";
		char *sever = "null";
		char *package = "null";
		char *vtype = "null";
		char *fixed = "null";
		char *ticket = "null";
		
		yajl_val obj = data->u.array.values[i];
		yajl_val d_pkgs = yajl_tree_get(obj, r_pkgs, yajl_t_array);
		
		if(!d_pkgs || !YAJL_IS_ARRAY(d_pkgs))
			continue;
		
		yajl_val statusobj = yajl_tree_get(obj, r_status, yajl_t_string);
		if(statusobj)
			status = YAJL_GET_STRING(statusobj);
		if(strcmp(status, "Vulnerable") != 0)
			continue;
		
		bool isinstalled = false;
		for(uint_fast16_t j=0; j < d_pkgs->u.array.len; j++){
			yajl_val pkgobj = d_pkgs->u.array.values[j];
			if(pkgobj)
				package = YAJL_GET_STRING(pkgobj);
			if((isinstalled = binsearch(installed, xlen, package)) != 0)
				break;
		}
		
		if(!isinstalled)
			continue;
		
		vulncount++;
		
		yajl_val versobj = yajl_tree_get(obj, r_version, yajl_t_string);
		yajl_val nameobj = yajl_tree_get(obj, r_name, yajl_t_string);
		yajl_val severobj = yajl_tree_get(obj, r_sever, yajl_t_string);
		
		if(versobj)
			version = YAJL_GET_STRING(versobj);
		if(nameobj)
			name = YAJL_GET_STRING(nameobj);
		if(severobj)
			sever = YAJL_GET_STRING(severobj);
		
		if(color){
			if(strcmp(sever, "High") == 0)
				COLSEVER=RED;
			else if(strcmp(sever, "Medium") == 0)
				COLSEVER=YEL;
			else if(strcmp(sever, "Low") == 0)
				COLSEVER=GRN;
			
			if(strcmp(status, "Vulnerable") == 0)
				COLSTAT=RED;
		}
		
		if(!printall){
			if(color)
				printf("%-20s%-20s%s%-12s" ESC "%s%-12s" ESC, package, version, COLSTAT, status, COLSEVER, sever);
			else
				printf("%-20s%-20s%-12s%-12s", package, version, status, sever);
			
			if(link)
				printf("https://security.archlinux.org/");
			
			printf("%-12s\n", name);
			
			continue;
		}
		
		yajl_val typeobj = yajl_tree_get(obj, r_type, yajl_t_string);
		yajl_val fixedobj = yajl_tree_get(obj, r_fixed, yajl_t_string);
		yajl_val ticketobj = yajl_tree_get(obj, r_ticket, yajl_t_string);
		yajl_val d_issues = yajl_tree_get(obj, r_issues, yajl_t_array);
		
		if(typeobj)
			vtype = YAJL_GET_STRING(typeobj);
		if(fixedobj)
			fixed = YAJL_GET_STRING(fixedobj);
		if(ticketobj)
			ticket = YAJL_GET_STRING(ticketobj);
		
		if(YAJL_IS_ARRAY(d_issues)){
			for(uint_fast16_t j=0; j < d_issues->u.array.len; j++){
				yajl_val issuesobj = d_issues->u.array.values[j];
				if(issuesobj){
					char *issue = YAJL_GET_STRING(issuesobj);
					if(color)
						printf("%-20s%-20s%s%-12s" ESC "%s%-12s" ESC "%-30s%-12s%-12s%-20s", package, version, COLSTAT, status, COLSEVER, sever, vtype, fixed, ticket, issue);
					else
						printf("%-20s%-20s%-12s%-12s%-30s%-12s%-12s%-20s", package, version, status, sever, vtype, fixed, ticket, issue);
					
					if(link)
						printf("https://security.archlinux.org/");
					
					printf("%-12s\n", name);
				}
			}
		}
	}
	
	if(printcount)
		printf("\n%lu vulnerable packages installed\n", vulncount);
	
	yajl_tree_free(node);
	alpm_utils_free(alpm_utils);
	alpm_list_free(pkglist);
	alpm_list_free(p);
	return 0;
}

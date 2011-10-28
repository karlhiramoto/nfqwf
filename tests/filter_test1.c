#include "HttpReq.h"
#include "ContentFilter.h"

int main(int argc, char *argv[])
{
	struct ContentFilter *cf;
	int ret;

	cf = ContentFilter_new();

	ret = ContentFilter_loadConfig(cf, "Xml file");

	ContentFilter_put(&cf);
	return 0;
}


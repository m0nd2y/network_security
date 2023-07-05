/*
** CYDF 2021350228 LEE-DONG-JUN
*/

#include <stdio.h>
#include <stdint.h>

uint32_t my_ntohl(uint32_t a)
{
	uint32_t result = ((a & 0xFF000000) >> 24) |
                      ((a & 0x00FF0000) >> 8) |
                      ((a & 0x0000FF00) << 8) |
                      ((a & 0x000000FF) << 24);
    return result;
}

int main(int argc, char *argv[])
{
	FILE *fp[2];									// declare fp
	uint32_t num[2];								// declare num

	if (argc != 3) 									// argv error
	{
		printf("[usage] add-nbo <file1> <file2>\n");
		return (0);
	}

	fp[0] = fopen(argv[1], "rb");					// read file1
    fp[1] = fopen(argv[2], "rb");					// read file2

	if (fp[0] == NULL | fp[1] == NULL)				// file open erorr
	{
		printf("file open error\n");
		return 0;
	}

	fread(&num[0], sizeof(num[0]), 1, fp[0]);		// read file1's number
    fread(&num[1], sizeof(num[1]), 1, fp[1]);		// read file2's number

    num[0] = my_ntohl(num[0]);						// convert network to host
    num[1] = my_ntohl(num[1]);						// convert network to host

	// ex > 1000(0x3e8) + 500(0x1f4) = 1500(0x5dc)
	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", \
		num[0], num[0], num[1], num[1], num[0]+num[1], num[0]+num[1]);

	fclose(fp[0]);									// close fp
    fclose(fp[1]);									// close fp

	return 0;
}
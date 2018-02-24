#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <err.h>

#define JPEG_BEGIN_MARKER	0xFFD8FFE1   //ff d8 ff e1
#define JPEG_EOF_MARKER		0xFFD9

// author tom@electric-sheep.org

int main(int argc, char **argv)
{
	char			*filename, filename_split[NAME_MAX+PATH_MAX+1];
	u_char			buf[1];
	u_char			b_byte1, b_byte2, b_byte3, b_byte4,
				e_byte1, e_byte2;
	int			fd_in, fd_out, eof_found, ret;
	register int		image_idx, data_idx, idx;
	off_t			file_size;
	struct stat		sbuf;


	if(argc == 1)
		errx(-1, "usage: %s <file>\n", argv[0]);


	b_byte1 = (JPEG_BEGIN_MARKER & 0xFF000000) >> 24;
	b_byte2 = (JPEG_BEGIN_MARKER & 0xFF0000)   >> 16;
	b_byte3 = (JPEG_BEGIN_MARKER & 0xFF00)     >> 8;
	b_byte4 =  JPEG_BEGIN_MARKER & 0xFF;
	e_byte1 = (JPEG_EOF_MARKER & 0xFF00)       >> 8;
	e_byte2 =  JPEG_EOF_MARKER & 0xFF;


	/* open file and get file size */
	filename = argv[1];
	if( (fd_in = open(filename, O_RDONLY)) < 0)
		err(-1, "unable to open file '%s'\n", filename);

	if(fstat(fd_in, &sbuf) < 0)
		err(-1, "unable to stat file '%s'\n", filename);

	file_size = sbuf.st_size;

#ifdef DEBUG
	fprintf(stderr, "\nFile: %s\n\tSize = %d\n\tbmark: 0x%X (0x%X, 0x%X)\n\temark: 0x%X (0x%X, 0x%X)\n",
		filename, file_size,
		JPEG_BEGIN_MARKER, b_byte1, b_byte2,
		JPEG_EOF_MARKER, e_byte1, e_byte2);
#endif


	image_idx = 1;
	idx = 0;
	while(read(fd_in, buf, sizeof(buf)) > 0)
	{
#ifdef DEBUG
		if(!(idx % 10))
			fprintf(stderr, "\n%06u: ", idx);
		fprintf(stderr, "0x%0.2X ", buf[0] & 0xFF);
#endif
		idx++;

		/* begin */
		if(buf[0] == b_byte1)
		{
			if(read(fd_in, buf, sizeof(buf)) <= 0) // EOF
			{
				printf("reached end-of-file...\n");
				break; // done
			}
#ifdef DEBUG
			if(!(idx % 10))
				fprintf(stderr, "\n%06u: ", idx);
			fprintf(stderr, "0x%0.2X ", buf[0] & 0xFF);
#endif
			idx++;

			if(buf[0] == b_byte2) // found marker
			{
				printf("found BEGIN marker\n");

				snprintf(filename_split, sizeof(filename_split), "%s-%03u.jpg", basename(filename), image_idx++);
				if( (fd_out = open(filename_split, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0)
					errx(-1, "can not creat file '%s'\n", filename_split);

				/* write begin marker */
				write(fd_out, (char *) &b_byte1, 1);
				write(fd_out, (char *) &b_byte2, 1);

				/* write jpeg data */
				eof_found = 0;
				data_idx  = 0;
				while( (ret = read(fd_in, buf, sizeof(buf))) > 0)
				{
#ifdef DEBUG
					if(!(idx % 10))
						fprintf(stderr, "\n%06u: ", idx);
					fprintf(stderr, "0x%0.2X ", buf[0] & 0xFF);
#endif
					idx++;

					data_idx++;
					write(fd_out, buf, sizeof buf);

					if(buf[0] == e_byte2 && eof_found)
					{
						printf("found EOF marker\n");
						break;
					}

					if(buf[0] == e_byte1)
						eof_found = 1;
					else
						eof_found = 0;

				}
				close(fd_out);
				//printf("wrote %u bytes of %u bytes to '%s'\n", data_idx, file_size-idx, filename_split);

				if(ret <= 0) // EOF
				{
					printf("reached end-of-file...\n");
					break; // done
				}
			} // b_byte2
			else
				lseek(fd_in, lseek(fd_in, 0, SEEK_CUR), SEEK_SET); // go one byte backwards
		} // b_byte1
	} // while(read)
	close(fd_in);

	exit(0);
}

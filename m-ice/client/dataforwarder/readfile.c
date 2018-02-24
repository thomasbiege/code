/*
** Read different file types.
** LAuS-part based on 'liblaussrv' source code.
*/
int intReadFile(char *cData, size_t DataSize, FILE *DataStream, u_int uiType)
{
  size_t  bytes_read = 0;


  DBG(0, "intReadFile: Start reading File (size: %d, type: 0x%0.2x)...", DataSize, uiType);

  /* check arguments */
  if(cData == NULL || DataSize <= 0 || DataStream == NULL)
  {
    DBG(2, "%s: intReadFile: Callers Argument invalid", cProgname);
    return(-1);
  }

  /* handling text files is simple... */
  if(uiType == FTF_FIREWALL || uiType == FTF_FILE || uiType == FTF_SCSLOG)
  {
    DBG(1, "%s: intReadFile: Filetype: Text File", cProgname);
    if( fgets(cData, DataSize, DataStream) == NULL && ferror(DataStream))
      return(-1);
    bytes_read = strlen(cData);
  }
#if defined(HAVE_LIBLAUSSRV)
  /* ... handling binary files is pain :) */
  else if(uiType == FTF_LAUS)
  {
    caddr_t                   mapped_file = NULL,
                              file_ptr = NULL,
                              pld_ptr = NULL,
                              pld_end = NULL;

    int                       skip_header = FALSE;

    size_t                    mapped_file_size = DataSize,
                              bytes_to_copy = 0,
                              bytes_totally_read = 0,
                              filehdr_len   = sizeof(struct laus_file_header),
                              rechdr_len    = sizeof(struct laus_record_header),
                              audhdr_len    = sizeof(struct aud_message);

    struct stat               stbuf;
    struct laus_file_header   *filehdr_ptr = NULL;
    struct laus_record_header *rechdr_ptr = NULL;
    struct aud_message        *audhdr_ptr = NULL;

    
    DBG(0, "%s: intReadFile: Filetype: LAuS File", cProgname);

    /*
    ** 0. CHECKING
    */
    DBG(0, "%s: intReadFile: 0. CHECKING FILE AND ARGUMENTS", cProgname);
    
    if(DataSize < rechdr_len + audhdr_len)
    {
      DBG(0, "%s: intReadFile: DataSize too small.", cProgname);
      return(-1);
    }

    if(ftell(DataStream) < filehdr_len)
    {
      if(ftell(DataStream) > 0)
      {
        DBG(0, "%s: intReadFile: File Header incomplete", cProgname);
        return(-1);
      }

      skip_header = TRUE;
    }

    if(fstat(fileno(DataStream), &stbuf) < 0)
    {
      DBG(2, "%s: intReadFile: Can not stat file", cProgname);
      return(-1);
    }
    if(stbuf.st_size < (skip_header ? filehdr_len : 0) + rechdr_len + audhdr_len)
    {
      DBG(0, "%s: intReadFile: File too small. Header missing.", cProgname);
      return(-1);
    }
    
    

    /*
    ** 1. MAP FILE PART INTO MEMORY
    */
    DBG(0, "%s: intReadFile: 1. MAP FILE PART INTO MEMORY", cProgname);
    
    if( (mapped_file = calloc(mapped_file_size, 1)) == NULL)
    {
        log_mesg(WARN_SYS, "%s: intReadFile: Cannot memory map file (calloc()) | Syserror", cProgname);
        return(-1);
    }
    if(fread_unlocked(mapped_file, 1, mapped_file_size, DataStream) != mapped_file_size)
    {
        log_mesg(WARN_SYS, "%s: intReadFile: Cannot memory map file (fread()) | Syserror", cProgname);
        free(mapped_file);
        return(-1);
    }

    
    /*
    ** 2. SET STRUCTURE POINTERS
    */
    DBG(0, "%s: intReadFile: 2. SET STRUCTURE POINTERS", cProgname);
    
    file_ptr = mapped_file;

    if(skip_header)
    {
      filehdr_ptr         = (struct laus_file_header *) file_ptr;
      file_ptr           += filehdr_len;
      bytes_totally_read += filehdr_len;
    }
    else
      filehdr_ptr = NULL;

    rechdr_ptr          = (struct laus_record_header *) file_ptr;
    file_ptr           += rechdr_len;
    bytes_totally_read += rechdr_len;

    audhdr_ptr          = (struct aud_message *) file_ptr;
    file_ptr           += audhdr_len;
    bytes_totally_read += audhdr_len;

    

    /*
    ** 3. CHECK HEADERS
    */
    DBG(0, "%s: intReadFile: 3. CHECK HEADERS", cProgname);
    
    /* empty timestamp -> end of record (bin-file) */
    /* we do not really need to check it as long as we are not */
    /* parsing in a loop, right? */
    /* let's use it as an error indicator */
    if(rechdr_ptr->r_time == 0)
    {
      DBG(0, "%s: intReadFile: End-Of-Record", cProgname);
      free(mapped_file);
      return(0);
    }
    if(rechdr_ptr->r_size > DataSize)
    {
      DBG(0, "%s: intReadFile: cData too small (%d) for full LAuS record (%d).", cProgname, DataSize, rechdr_ptr->r_size);
      free(mapped_file);
      return(-1);
    }

    DBG(0, "%s: intReadFile: Audit Message Size: %d", cProgname, audhdr_ptr->msg_size);

    if(audhdr_ptr->msg_size == 0)
    {
      DBG(0, "%s: intReadFile: Audit Message is empty.", cProgname);
      free(mapped_file);
      return(-1);
    }

    if (audhdr_ptr->msg_size > rechdr_ptr->r_size)
    {
      DBG(0, "%s: intReadFile: Audit Message was truncated (msg_size (%d) > r_size (%d))", cProgname, audhdr_ptr->msg_size, rechdr_ptr->r_size);
      free(mapped_file);
      return(-1);
    }

    
    /*
    ** 4. HANDLE PAYLOAD
    */
    DBG(0, "%s: intReadFile: 4. HANDLE PAYLOAD", cProgname);

    pld_ptr       = file_ptr;
    pld_end       = pld_ptr + (audhdr_ptr->msg_size - audhdr_len);

    bytes_to_copy = audhdr_ptr->msg_size; // msg_size includes header length and payload length

    if(stbuf.st_size < (skip_header ? filehdr_len : 0) + rechdr_len + audhdr_ptr->msg_size)
    {
      DBG(0, "%s: intReadFile: File too small. Payload missing.", cProgname);
      free(mapped_file);
      return(-1);
    }

    
    /*
    ** 5. COPY MESSAGE TO CALLER
    */
    DBG(0, "%s: intReadFile: 5. COPY MESSAGE TO CALLER", cProgname);

    memcpy(cData, (char *) audhdr_ptr, bytes_to_copy);
    DBG(0, "%s: intReadFile: bytes_to_copy = %d", cProgname, bytes_to_copy);

    bytes_read          = (skip_header ? filehdr_len : 0) + rechdr_len + bytes_to_copy;
    bytes_totally_read += (audhdr_ptr->msg_size - audhdr_len);

    DBG(0, "%s: intReadFile: bytes_read = %d", cProgname, bytes_read);

    /* done with ONE LAuS record */
    if(DataSize > bytes_totally_read)
    {
      /* just rewind the file */
      if(fseek(DataStream, DataSize - bytes_totally_read, SEEK_CUR) < 0)
        log_mesg(WARN_SYS, "%s: intReadFile: Cannot set file offset pointer | Syserror", cProgname);
    }

    free(mapped_file);
  }
#endif // LAuS part
  else
  {
    DBG(1, "%s: intReadFile: Filetype: UNKNOWN", cProgname);
    return(-1);
  }

  DBG(1, "%s: intReadFile: ...reading File done.", cProgname);

  return(bytes_read);
}

    const xmlChar *ret;
    int len = 0, l;
    int c;
    int maxLength = (ctxt->options & XML_PARSE_HUGE) ?
                    XML_MAX_TEXT_LENGTH :
                    XML_MAX_NAME_LENGTH;
    int old10 = (ctxt->options & XML_PARSE_OLD10) ? 1 : 0;

    /*
     * Handler for more complex cases
     */
    c = xmlCurrentChar(ctxt, &l);
    if (!xmlIsNameStartChar(c, old10))
        return(NULL);
    len += l;
    NEXTL(l);
    c = xmlCurrentChar(ctxt, &l);
    while (xmlIsNameChar(c, old10)) {
        if (len <= INT_MAX - l)
            len += l;
        NEXTL(l);
        c = xmlCurrentChar(ctxt, &l);
    }
    if (len > maxLength) {
        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Name");
        return(NULL);
    }
    if (ctxt->input->cur - ctxt->input->base < len) {
        /*

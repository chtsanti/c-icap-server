
%{
#include "header.h"
%}

%ignore ci_options_headers;
%ignore ci_request_headers;
%ignore ci_responce_headers;
%ignore ci_common_headers;
%ignore ci_headers_pack;
%ignore ci_headers_unpack;
%ignore sizeofheader;

%ignore ci_encaps_entity_t;
%ignore ci_encaps_entity;
%ignore ci_encaps_entities;
%ignore mk_encaps_entity;
%ignore destroy_encaps_entity;
%ignore get_encaps_type;
%ignore sizeofencaps;

%include "header.h"

%extend ci_headers_list {
    ci_headers_list() {
        return ci_headers_create();
    }
    ~ci_headers_list() {
        ci_headers_destroy($self);
    }

    int empty() {
        return ci_headers_is_empty($self);
    }

    void reset() {
        ci_headers_reset($self);
    }

    const char *add(const char *header) {
        return ci_headers_add($self, header);
    }

    int add_headers(ci_headers_list_t *headers) {
        return ci_headers_addheaders($self, headers) != 0;
    }

    int remove(const char *head) {
        return ci_headers_remove($self, head) != 0;
    }

    const char *search(const char *head) {
        return ($self)->packed == 0 ? ci_headers_search($self, head) : NULL;
    }

    const char *value(const char *head) {
        return ($self)->packed == 0 ? ci_headers_value($self, head) : NULL;
    }

    const char *first_line() {
        return ($self)->packed == 0 ? ci_headers_first_line($self) : NULL;
    }
 };

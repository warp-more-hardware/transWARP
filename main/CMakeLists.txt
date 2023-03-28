# Embed the server root certificate into the final binary
idf_build_get_property(project_dir PROJECT_DIR)
idf_component_register(SRCS "transWARP.c"
                    "simple_ota.c"
                    #"file_server.c"
                    INCLUDE_DIRS "." "include"
                    EMBED_TXTFILES ${project_dir}/server_certs/ca_cert.pem)
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")


function(SERIAL_GENERATE idl_file out_name dir)
  find_program(GENERATOR idl-serial-code-gen)
  set(PROC_ARGS "${idl_file} ${out_name} ${dir}")

  exec_program(${GENERATOR} ARGS ${PROC_ARGS})
endfunction()

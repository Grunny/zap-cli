_zap-cli_completion() {
    COMPREPLY=( $( COMP_WORDS="${COMP_WORDS[*]}" \
                   COMP_CWORD=$COMP_CWORD \
                   _ZAP_CLI_COMPLETE=complete $1 ) )
    return 0
}

complete -F _zap-cli_completion -o default zap-cli;

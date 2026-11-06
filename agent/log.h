#ifndef BC_AGENT_LOG_H
#define BC_AGENT_LOG_H
/* Removes --log-level/--log-categories from argv and installs the stderr sink. */
int bc_agent_log_options(int *argc, char **argv);
#endif

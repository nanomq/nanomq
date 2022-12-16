#include <stdio.h>
#include <assert.h>

#include "include/broker.h"

int main()
{
    int rv = broker_start(0, NULL);

    assert(rv == 0);

    return 0;
}
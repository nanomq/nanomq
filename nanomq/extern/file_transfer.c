/*
 * This is an example of how to use the MQTT client library to send a file to
 * the broker using EMQX's the file transfer extension.
 *
 * The EMQX file transfer extension documentation is available here:
 * https://www.emqx.io/docs/en/v5/file-transfer/introduction.html
 *
 * This example reads a file from the file system and publishes it to the
 * broker (the file transfer feature has to be enabled in the EMQX
 * configuration). The user can specify the file path, file id, file name etc
 * as command line parameters. Run the program with the --help flag to see the
 * list of options.
 *
 * Change the DEBUG macro to 1 to see debug messages.
 */

/*
 * TODO: In order to know that the broker accepted the file and the individual
 * messages one has to check the PUBACK reason code. This is not implemented
 * in this example so even if everything seems to work we don't know that the
 * file has been stored by the broker (without checking with e.g., the HTTP
 * API). The PUBACK reason code is a MQTT v5 feature so in order to fix this we
 * would first have to make sure that the client connects with the MQTT v5
 * protocol and then check the PUBACK reason code fore each message. It seems
 * like this could be done by setting a handler with MQTTClient_setPublished()
 * https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/_m_q_t_t_client_8h.html#a9f13911351a3de6b1ebdabd4cb4116ba
 * . Unfortunately I had some problem with connecting with MQTT v5 so I have
 * not been able to test this yet. See also:
 * https://github.com/emqx/MQTT-Client-Examples/pull/112#discussion_r1253421492
 */


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <MQTTClient.h>

#define CLIENTID    "c-client"
#define TIMEOUT     100000L
#define DEBUG       0


int send_file(MQTTClient client,
              char *file_path,
              char *file_id,
              char *file_name,
              unsigned long expire_time_s_since_epoch,
              unsigned long segments_ttl_seconds) {
    FILE *fp = fopen(file_path, "rb");
    int rc;
    int qos = 1;
    const size_t buf_size = 2048;
    if (fp == NULL) {
        printf("Failed to open file %s\n", file_path);
        return -1;
    }
    // Get file size
    fseek(fp, 0L, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    // Create payload for initial message 
    char payload[buf_size];
    char expire_at_str[128];
    char segments_ttl_str[128];
    if (expire_time_s_since_epoch == -1) {
        expire_at_str[0] = '\0';
    } else {
        // No need to check return value since we know the buffer is large enough
        snprintf(expire_at_str,
                128,
                "  \"expire_at\": %ld,\n",
                expire_time_s_since_epoch);
    }
    if (segments_ttl_seconds == -1) {
        segments_ttl_str[0] = '\0';
    } else {
        // No need to check return value since we know the buffer is large enough
        snprintf(segments_ttl_str,
                128,
                "  \"segments_ttl\": %ld,\n",
                segments_ttl_seconds);
    }
    rc = snprintf(
            payload,
            buf_size,
            "{\n"
            "  \"name\": \"%s\",\n"
            "  \"size\": %ld,\n"
            "%s"
            "%s"
            "  \"user_data\": {}\n"
            "}",
            file_name,
            file_size,
            expire_at_str,
            segments_ttl_str);
    if (rc < 0 || rc >= buf_size) {
        printf("Failed to create payload for initial message\n");
        return -1;
    }
    // Create topic of the form $file/{file_id}/init for initial message
    char topic[buf_size];
    MQTTClient_deliveryToken token;
    rc = snprintf(topic, buf_size, "$file/%s/init", file_id);
    if (rc < 0 || rc >= buf_size) {
        printf("Failed to create topic for initial message\n");
        return -1;
    }
    // Publish initial message
    if (DEBUG) {
        printf("Publishing initial message to topic %s\n", topic);
        printf("Payload: %s\n", payload);
    }
    rc = MQTTClient_publish(client, topic, strlen(payload), payload, 1, 0, &token);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("Failed to publish message, return code %d\n", rc);
        return -1;
    }
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("Failed to publish message, return code %d\n", rc);
        return -1;
    }
    // Read binary chunks of max size 1024 bytes and publish them to the broker
    // The chunks are published to the topic of the form $file/{file_id}/{offset}
    // The chunks are read into the payload
    size_t chunk_size = 1024;
    size_t offset = 0;
    size_t read_bytes;
    while ((read_bytes = fread(payload, 1, chunk_size, fp)) > 0) {
        rc = snprintf(topic, buf_size, "$file/%s/%lu", file_id, offset);
        if (rc < 0 || rc >= buf_size) {
            printf("Failed to create topic for file chunk\n");
            return -1;
        }
        if (DEBUG) {
            printf("Publishing file chunk to topic %s offset %lu\n", topic, offset);
        }
        rc = MQTTClient_publish(client, topic, read_bytes, payload, 1, 0, &token);
        if (rc != MQTTCLIENT_SUCCESS) {
            printf("Failed to publish file chunk, return code %d\n", rc);
            return -1;
        }
        rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
        if (rc != MQTTCLIENT_SUCCESS) {
            printf("Failed to publish file chunk, return code %d\n", rc);
            return -1;
        }
        offset += read_bytes;
    }
    // Check if we reached the end of the file
    if (feof(fp)) {
        if (DEBUG) {
            printf("Reached end of file\n");
        }
    } else {
        printf("Failed to read file\n");
        return -1;
    }
    fclose(fp);
    // Send final message to the topic $file/{file_id}/fin/{file_size} with an empty payload
    rc = snprintf(topic, buf_size, "$file/%s/fin/%ld", file_id, file_size);
    if (rc < 0 || rc >= buf_size) {
        printf("Failed to create topic for final message\n");
        return -1;
    }
    if (DEBUG) {
        printf("Publishing final message to topic %s\n", topic);
    }
    rc = MQTTClient_publish(client, topic, 0, "", 1, 0, &token);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("Failed to publish final message, return code %d\n", rc);
        return -1;
    }
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("Failed to publish final message, return code %d\n", rc);
        return -1;
    }
    return 0;
}

void print_usage() {
    printf("usage: mqtt_c_file_transfer [-h|--help] [--port PORT] [--host HOST] [--username USERNAME] [--password PASSWORD] --file FILE [--file-name FILE_NAME] [--segments-ttl-seconds SEGMENTS_TTL_SECONDS] [--expire-after-seconds EXPIRE_AFTER_SECONDS] --file-id FILE_ID [--client-id CLIENT_ID]");
}

/*
    Read command line arguments into write back variables and fill in default
    values.
*/
void read_command_line_arguments(
        int argc,
        char *argv[],
        char **file_path,
        char **file_id,
        char **username,
        char **password,
        char **file_name,
        char **client_id,
        char **host,
        int *port,
        long *segments_ttl_seconds,
        long *expire_after_seconds) {
    // Fill in default values
    *file_name = "myfile.txt";
    *host = "localhost";
    *port = 1883;
    *segments_ttl_seconds = -1;
    *expire_after_seconds = -1;
    *client_id = CLIENTID;
    *username = NULL;
    *password = NULL;
    // Check if -h or --help is passed in
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage();
        exit(0);
    }
    *file_path = NULL;
    *file_id = NULL;
    // Read command line arguments
    for (int i = 1; i < argc; i+=2) {
        if (strcmp(argv[i], "--file") == 0) {
            *file_path = argv[i + 1];
        } else if (strcmp(argv[i], "--file-id") == 0) {
            *file_id = argv[i + 1];
        } else if (strcmp(argv[i], "--file-name") == 0) {
            *file_name = argv[i + 1];
        } else if (strcmp(argv[i], "--client-id") == 0) {
            *client_id = argv[i + 1];
        } else if (strcmp(argv[i], "--username") == 0) {
            *username = argv[i + 1];
        } else if (strcmp(argv[i], "--password") == 0) {
            *password = argv[i + 1];
        } else if (strcmp(argv[i], "--host") == 0) {
            *host = argv[i + 1];
        } else if (strcmp(argv[i], "--port") == 0) {
            *port = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--segments-ttl-seconds") == 0) {
            *segments_ttl_seconds = atol(argv[i + 1]);
        } else if (strcmp(argv[i], "--expire-after-seconds") == 0) {
            *expire_after_seconds = atol(argv[i + 1]);
        } else {
            printf("Unknown argument %s\n", argv[i]);
            print_usage();
            exit(1);
        }
        if (DEBUG) {
            printf("Argument %s %s\n", argv[i], argv[i + 1]);
        }
    }
    // Check if --file and --file-id are passed in
    if (*file_path == NULL || *file_id == NULL) {
        printf("Missing required arguments\n");
        print_usage();
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    int rc;
    MQTTClient client;
    // Declare variables to store command line arguments
    char *file_path;
    char *file_id;
    char *file_name;
    char *client_id;
    char *host;
    int port;
    char *username;
    char *password;
    long segments_ttl_seconds;
    long expire_after_seconds;
    // Read command line arguments
    read_command_line_arguments(
            argc,
            argv,
            &file_path,
            &file_id,
            &username,
            &password,
            &file_name,
            &client_id,
            &host,
            &port,
            &segments_ttl_seconds,
            &expire_after_seconds);
    if (DEBUG) {
        // Print command line arguments
        printf("file_path: %s\n", file_path);
        printf("file_id: %s\n", file_id);
        printf("file_name: %s\n", file_name);
        printf("client_id: %s\n", client_id);
        printf("host: %s\n", host);
        printf("port: %d\n", port);
        if (username != NULL) {
            printf("username: %s\n", username);
        }
        if (password != NULL) {
            printf("password: %s\n", password);
        }
        printf("segments_ttl_seconds: %ld\n", segments_ttl_seconds);
        printf("expire_after_seconds: %ld\n", expire_after_seconds);
    }
    // Construct address string from host and port
    char address[2048];
    rc = snprintf(address, 2048, "tcp://%s:%d", host, port);
    if (rc < 0 || rc >= 2048) {
        printf("Failed to construct address string\n");
        exit(1);
    }
    // Create client
    MQTTClient_create(&client, address, client_id, 0, NULL);
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.username = username;
    conn_opts.password = password;
    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        exit(1);
    } else {
        if (DEBUG) {
            printf("Connected to MQTT Broker!\n");
        }
    }
    // Calculate expire time
    unsigned long expire_time_s_since_epoch;
    if (expire_after_seconds == -1) {
        expire_time_s_since_epoch = -1;
    } else {
        expire_time_s_since_epoch = time(NULL) + expire_after_seconds;
    }
    // Send file
    int result = send_file(client,
                           file_path,
                           file_id,
                           file_name,
                           expire_time_s_since_epoch,
                           segments_ttl_seconds);
    MQTTClient_disconnect(client, TIMEOUT);
    MQTTClient_destroy(&client);
    if (result == 0) {
        return 0;
    } else {
        return 1;
    }
}

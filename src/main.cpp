#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <vector>

extern "C"
{
#include <unistd.h>
#include <errno.h>
#include <security/pam_appl.h>
}

#define UNIMPLEMENTED()             \
    std::cout << "Unimplemented\n"; \
    std::exit(-1);

int callback(int number_of_messages, const struct pam_message **messages, struct pam_response **responses, void *context)
{
    struct pam_response *response = static_cast<pam_response *>(malloc(number_of_messages * sizeof(pam_response)));

    if (response == nullptr)
    {
        return PAM_CONV_ERR;
    }

    for (int idx = 0; idx < number_of_messages; idx++)
    {
        switch (messages[idx]->msg_style)
        {
        case PAM_PROMPT_ECHO_OFF:
            response[idx].resp = strdup(getpass(messages[idx]->msg));
            response[idx].resp_retcode = 0;

            break;
        case PAM_PROMPT_ECHO_ON:
            UNIMPLEMENTED();

            break;
        case PAM_ERROR_MSG:
            UNIMPLEMENTED();

            break;
        case PAM_TEXT_INFO:
            UNIMPLEMENTED();

            break;
        default:
            free(response);

            return PAM_CONV_ERR;
        }
    }

    *responses = response;

    return PAM_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc <= 1)
    {
        std::cout << "Usage: sudo <program> [parameters]\n";

        return -1;
    }

    pam_conv pam_conversation = {
        &callback,
        nullptr,
    };

    pam_handle_t *pam_handle{};

    if (pam_start("ssudo", "bakamono", &pam_conversation, &pam_handle) != PAM_SUCCESS)
    {
        std::cout << "PAM initialization failed\n";

        return -2;
    }

    int status{};

    status = pam_authenticate(pam_handle, 0);

    if (status == PAM_SUCCESS)
    {
        std::cout << "Authenticated successfully\n";
    }
    else
    {
        std::cerr << "Authentication failed: " << pam_strerror(pam_handle, status) << std::endl;

        return -3;
    }

    if (pam_end(pam_handle, status) != PAM_SUCCESS)
    {
        std::cout << "PAM deinitialization failed\n";

        return -4;
    }

    auto path = std::filesystem::path(std::string(argv[1]));

    if (path.is_absolute() && !std::filesystem::exists(path))
    {
        std::cout << "XD\n";

        std::cout << path.string() << " doesn't exist\n";

        return -5;
    }

    bool has_resolved = false;

    if (path.is_relative())
    {
        char *path_env_variable_cstr = getenv("PATH");

        if (path_env_variable_cstr == nullptr)
        {
            return -6;
        }

        auto path_env_variable = std::string(path_env_variable_cstr);

        size_t size = path_env_variable.size();
        size_t last_colon_position = 0;
        size_t colon_position = path_env_variable.find(':');

        auto current_path = std::filesystem::path(path_env_variable.substr(last_colon_position, colon_position - last_colon_position));

        current_path.append(argv[1]);

        if (std::filesystem::exists(current_path))
        {
            path = current_path;
            has_resolved = true;
        }
        else
        {
            while (colon_position != std::string::npos)
            {
                last_colon_position = colon_position + 1;
                colon_position = path_env_variable.find(':', colon_position + 1);

                auto current_path = std::filesystem::path(path_env_variable.substr(last_colon_position, colon_position - last_colon_position));

                current_path.append(argv[1]);

                if (std::filesystem::exists(current_path))
                {
                    path = current_path;
                    has_resolved = true;

                    break;
                }
            }
        }
    }

    if (path.is_relative() && !has_resolved)
    {
        std::cout << path.string() << " doesn't exist\n";

        return -7;
    }

    std::vector<char *> arguments;

    for (size_t i = 1; i < argc; i++)
    {
        arguments.push_back(argv[i]);
    }

    arguments.push_back(nullptr);

    char *environment_variables[] = {
        nullptr,
    };

    if (setuid(0) != 0)
    {
        perror("setuid");

        return -8;
    }

    if (setgid(0) != 0)
    {
        perror("setgid");

        return -9;
    }

    std::string path_string = path.string();

    if (execve(path_string.c_str(), arguments.data(), environment_variables) != 0)
    {
        perror("execve");

        return -10;
    }

    return 0;
}

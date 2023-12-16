# Tutorial: Azure App Registration for Mojang Authentication

Follow this [tutorial](https://scribehow.com/shared/Creating_a_new_Azure_app_registration_and_submitting_for_Minecraft_access_approval__Ev1zNgspTgOWN2VpbB1klw) to create an Azure Application and request access to Mojang authentication.

## Next Steps - Edit SRC

### `app/elizon/authhelper/AuthHelper`

Example Integration

### `app/elizon/authhelper/process/AuthProcess`

API for using the Processes

### `app/elizon/authhelper/impl/ProcessDetails`

Interface Class for structure

### `app/elizon/authhelper/impl/MinecraftMSLiveAuthProcess`

Class with Authentication process for Minecraft launchers and account switchers

```plaintext
29: Change Client ID to the one given on Azure
35: Same here
32: Leave it as is or change the port
36: Same here
38: Adjust timeout for auth-wait
460: Adjust finishing message on auth
535: Same here
```

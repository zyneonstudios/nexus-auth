
> Use this tutorial to create a Azure Application and request access to Mojang auth.

https://scribehow.com/shared/Creating_a_new_Azure_app_registration_and_submitting_for_Minecraft_access_approval__Ev1zNgspTgOWN2VpbB1klw

> Next Steps - Edit SRC

app <hr>
  elizon <hr>
    authhelper <hr>
      - AuthHelper 
      <p>Example Integration</p><hr>
      process <hr>
      - AuthProcess
      <p>API for using the Processes</p><hr>
      impl <hr>
      - ProcessDetails
      <p>Interface Class for structure</p>
      - MinecraftMSLiveAuthProcess
      <p>Class with Authentication process for minecraft launchers and account switchers</p>
      29: Change Client ID to given on Azure
      35: Same here
      32: Leave it as is or change port
      36: Same here
      38: Adjust timeout for auth-wait
      460: Adjust finishing message on auth
      535: Same here

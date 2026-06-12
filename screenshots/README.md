# Capturas de pantalla — DTP Attack

Capturas del laboratorio en orden de demostración.

| # | Archivo de Evidencia | Descripción Técnica Detallada |
| --- | --- | --- |
| 1 | [01_topologia.png](/screenshots/01_topologia.png) | Vista de la topología funcional en PNETLab. Se validan las etiquetas de nombres, matrícula (`20250737`), interfaces conectadas y el direccionamiento de la subred. |
| 2 | [02_switchport_inicial.png](/screenshots/02_switchport_inicial.png) | Ejecución de `show interfaces ethernet 0/0 switchport` previo al ataque. Muestra el estado operativo inicial en `static access` sin enlaces troncales activos. |
| 3 | [03_ejecucion_ataque.png](/screenshots/03_ejecucion_ataque.png) | Consola de Kali Linux ejecutando el script. Muestra el proceso de inyección continua de paquetes estructurados DTP Dynamic Desirable. |
| 4 | [04_interfaces_trunk.png](/screenshots/04_interfaces_trunk.png) | Salida del comando `show interfaces trunk` en el switch en caliente, confirmando que la interfaz se transformó en un puerto Trunk de forma no autorizada. |
| 5 | [05_vlan_hopping_ping.png](/screenshots/05_vlan_hopping_ping.png) | Creación de la subinterfaz lógica etiquetada en Kali Linux y ping exitoso hacia la IP del SERVER (`20.25.37.10`), demostrando el salto exitoso de la VLAN. |
| 6 | [06_mitigacion_nonegotiate.png](/screenshots/06_mitigacion_nonegotiate.png) | Aplicación de comandos defensivos en la CLI de Cisco configurando el puerto de forma fija en acceso y deshabilitando explícitamente la negociación DTP. |

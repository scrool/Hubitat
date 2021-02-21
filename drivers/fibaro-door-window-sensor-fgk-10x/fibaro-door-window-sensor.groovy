/*****************************************************************************************************************
 *
 *  Name: Fibaro Door/Window Sensor
 *
 *  Author: Pavol Babinčák (scrool)
 *
 *  Copyright: Pavol Babinčák (scrool)
 *
 *  Date: 2022-01-14
 *
 *  Version: 1.00
 *
 *  Description: Hubitat Elevation platform device handler for the Fibaro
 *               Door/Window sensor (FGK-10X) (EU) with support of DS18B20
 *               temperature sensor installed.
 *
 *               This code is derived from Fibaro Flood Sensor Advanced by
 *               David Lomas (codersaur) and Fibaro Door/Window Sensor ZW5 for
 *               Samsung SmartThings and code by Bryan Copeland (djdizzyd).
 *               Original copyrights and identification follow.
 *
 *  Source: https://github.com/scrool/Hubitat
 *****************************************************************************************************************/

/*****************************************************************************************************************
 *  Copyright: David Lomas (codersaur)
 *
 *  Name: Fibaro Flood Sensor Advanced
 *
 *  Author: David Lomas (codersaur)
 *
 *  Date: 2017-03-02
 *
 *  Version: 1.00
 *
 *  Source: https://github.com/codersaur/SmartThings/tree/master/devices/fibaro-flood-sensor
 *****************************************************************************************************************/

/*****************************************************************************************************************
 *  Fibaro Door/Window Sensor ZW5
 *
 *  Copyright 2016 Fibaro Group S.A.
 *
 *  Source: https://github.com/SmartThingsCommunity/SmartThingsPublic/blob/master/devicetypes/fibargroup/fibaro-door-window-sensor-zw5-with-temperature.src
 *****************************************************************************************************************/

/*****************************************************************************************************************
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *   for the specific language governing permissions and limitations under the License.
 *****************************************************************************************************************/

/*
 * TODO: signed/unsigned?, security?, without thermometer?, sync all is not bool
 *
 */
metadata {
    definition (name: "Fibaro Door/Window Sensor", namespace: "scrool", author: "Pavol Babinčák") {
        capability "ContactSensor"
        capability "TamperAlert"
        capability "TemperatureMeasurement"
        capability "Battery"
        capability "Sensor"

        // Standard (Capability) Attributes:
        attribute "battery", "number"
        attribute "contact", "enum", ["closed", "open"]
        attribute "tamper", "enum", ["clear", "detected"]
        attribute "temperature", "number"

        // Custom Attributes:
        attribute "logMessage", "string"        // Important log messages.
        attribute "syncPending", "number"       // Number of config items that need to be synced with the physical device.

        // Custom Commands:
        command "sync"

        fingerprint deviceId: "0x0701", inClusters: "0x5E,0x85,0x59,0x22,0x20,0x80,0x70,0x56,0x5A,0x7A,0x72,0x8E,0x71,0x73,0x98,0x2B,0x9C,0x30,0x31,0x86,0x84", deviceJoinName: "Fibaro FGK-10x with temperature sensor"

        fingerprint deviceId: "0x0701", inClusters: "0x5E,0x85,0x59,0x22,0x20,0x80,0x70,0x56,0x5A,0x7A,0x72,0x8E,0x71,0x73,0x98,0x2B,0x9C,0x30,0x86,0x84", deviceJoinName: "Fibaro FGK-10x"
    }

    preferences {
        parameterMap().findAll{(it.id as Integer) != 54}.each {
            input (
                    name: "configParam${it.id}",
                    title: "${it.id}. ${it.title}",
                    description: "${it.descr}\nDefault: $it.def",
                    type: it.type,
                    options: it.options,
                    range: (it.min != null && it.max != null) ? "${it.min}..${it.max}" : null,
                    defaultValue: it.def,
                    required: false
            )
        }

        input (
            name: "configLoggingLevelIDE",
            title: "IDE Live Logging Level: Messages with this level and higher will be logged to the IDE.",
            type: "enum",
            options: [
                "0" : "None",
                "1" : "Error",
                "2" : "Warning",
                "3" : "Info",
                "4" : "Debug",
                "5" : "Trace"
            ],
//                defaultValue: "3", // iPhone users can uncomment these lines!
            required: true
        )

        input (
            name: "configLoggingLevelDevice",
            title: "Device Logging Level: Messages with this level and higher will be logged to the logMessage attribute.",
            type: "enum",
            options: [
                "0" : "None",
                "1" : "Error",
                "2" : "Warning"
            ],
//                defaultValue: "2", // iPhone users can uncomment these lines!
            required: true
        )

        input (
            name: "configSyncAll",
            title: "Force Full Sync: All device parameters and association groups will be re-sent to the device. " +
            "This will happen at next wake up or on receipt of an alarm/temperature report.",
            type: "boolean",
            defaultValue: false,
            required: true
        )


    }
}

/**
 *  parse()
 *
 *  Called when messages from the device are received by the hub. The parse method is responsible for interpreting
 *  those messages and returning event definitions (and command responses).
 *
 *  As this is a Z-wave device, zwave.parse() is used to convert the message into a command. The command is then
 *  passed to zwaveEvent(), which is overloaded for each type of command below.
 *
 *  Parameters:
 *   String      description        The raw message from the device.
 **/
def parse(description) {
    logger("parse(): Parsing raw message: ${description}","trace")

    def result = []

    if (description.startsWith("Err 106")) {
        result = createEvent(
                descriptionText: "Failed to complete the network security key exchange. If you are unable to receive data from it, you must remove it from your network and add it again.",
                eventType: "ALERT",
                name: "secureInclusion",
                value: "failed",
                displayed: true,
        )
    } else if (description == "updated") {
        return null
    } else {
        def cmd = zwave.parse(description, cmdVersions())
        if (cmd) {
            log.debug "${device.displayName} - Parsed: ${cmd}"

            result += zwaveEvent(cmd)

            // Attempt sync(), but only if the received message is an unsolicited command:
            if (
                (cmd.commandClassId == 0x20 )  // Basic
                || (cmd.commandClassId == 0x30 )  // Sensor Binary
                || (cmd.commandClassId == 0x31 )  // Sensor Multilevel
                || (cmd.commandClassId == 0x60 )  // Multichannel (SensorMultilevelReport arrive in Multichannel)
                || (cmd.commandClassId == 0x71 )  // Alarm
                || (cmd.commandClassId == 0x84 & cmd.commandId == 0x07) // WakeUpNotification
                || (cmd.commandClassId == 0x9C )  // Sensor Alarm
            ) { sync() }

        } else {
            logger("parse(): Could not parse raw message: ${description}","error")
        }
    }

    // Send wakeUpNoMoreInformation command
    if (device.latestValue("syncPending").toInteger() == 0) {
        result << response(zwave.wakeUpV1.wakeUpNoMoreInformation())
    }

    return result
}

/*****************************************************************************************************************
 *  Z-wave Event Handlers.
 *****************************************************************************************************************/

/**
 *  zwaveEvent( COMMAND_CLASS_BASIC V1 (0x20) : BASIC_SET )
 *
 *  The Basic Set command is used to set a value in a supporting device.
 *
 *  Action: Log contact event.
 *
 *  cmd attributes:
 *    Short    value
 *      0x00       = Off       = closed
 *      0x??       =           = open
 *
 *  Example: BasicSet(value: 0)
 **/
def zwaveEvent(hubitat.zwave.commands.basicv1.BasicSet cmd) {
    logger("zwaveEvent(): Basic Set received: ${cmd}","trace")

    def map = [:]

    map.name = "contact"
    map.value = cmd.value ? "closed" : "open"
    map.descriptionText = "${device.displayName} is ${map.value}"

    return createEvent(map)
}

/**
 *  zwaveEvent( COMMAND_CLASS_SENSOR_MULTILEVEL V? (0x31) : SENSOR_MULTILEVEL_REPORT (0x0?) )
 *
 *  The Multilevel Sensor Report Command is used by a multilevel sensor to advertise a sensor reading.
 *
 *  Action: Raise appropriate type of event (and disp event) and log an info message.
 *
 *  cmd attributes:
 *    Short         precision           Indicates the number of decimals.
 *                                      E.g. The decimal value 1025 with precision 2 is therefore equal to 10.25.
 *    Short         scale               Indicates what unit the sensor uses.
 *    BigDecimal    scaledSensorValue   Sensor value as a double.
 *    Short         sensorType          Sensor Type (8 bits).
 *    List<Short>   sensorValue         Sensor value as an array of bytes.
 *    Short         size                Indicates the number of bytes used for the sensor value.
 *
 *  Example: SensorMultilevelReport(precision: 2, scale: 0, scaledSensorValue: 20.67, sensorType: 1, sensorValue: [0, 0, 8, 19], size: 4)
 **/
def zwaveEvent(hubitat.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd) {
    logger("zwaveEvent(): SensorMultilevelReport received: ${cmd}","trace")

    def result = []
    def map = [ displayed: true, value: cmd.scaledSensorValue.toString() ]
    def dispMap = [ displayed: false ]

    switch (cmd.sensorType) {
        case 1:  // Air Temperature (V1)
            map.name = "temperature"
            map.unit = (cmd.scale == 1) ? "F" : "C"
            break
        default:
            logger("zwaveEvent(): SensorMultilevelReport with unhandled sensorType: ${cmd}","warn")
            map.name = "unknown"
            map.unit = "unknown"
            break
    }

    logger("New sensor reading: Name: ${map.name}, Value: ${map.value}, Unit: ${map.unit}","info")

    result << createEvent(map)
    if (dispMap.name) { result << createEvent(dispMap) }

    return result
}

/**
 *  zwaveEvent( COMMAND_CLASS_CRC16_ENCAP (0x56) : CRC_16_ENCAP (0x01) )
 *
 *  The CRC-16 Encapsulation Command Class is used to encapsulate a command with an additional CRC-16 checksum
 *  to ensure integrity of the payload. The purpose for this command class is to ensure a higher integrity level
 *  of payloads carrying important data.
 *
 *  Action: Extract the encapsulated command and pass to zwaveEvent().
 *
 *  Note: Validation of the checksum is not necessary as this is performed by the hub.
 *
 *  cmd attributes:
 *    Integer      checksum      Checksum.
 *    Short        command       Command identifier of the embedded command.
 *    Short        commandClass  Command Class identifier of the embedded command.
 *    List<Short>  data          Embedded command data.
 *
 *  Example: Crc16Encap(checksum: 125, command: 2, commandClass: 50, data: [33, 68, 0, 0, 0, 194, 0, 0, 77])
 **/
def zwaveEvent(hubitat.zwave.commands.crc16encapv1.Crc16Encap cmd) {
    logger("zwaveEvent(): CRC-16 Encapsulation Command received: ${cmd}","trace")

    //TODO: https://community.smartthings.com/t/handling-crc-16-encapsulation-commands-crc16encap/76931/7 ?
    def version = cmdVersions()[cmd.commandClass as Integer]
    def ccObj = version ? zwave.commandClass(cmd.commandClass, version) : zwave.commandClass(cmd.commandClass)
    def encapsulatedCommand = ccObj?.command(cmd.command)?.parse(cmd.data)
    if (encapsulatedCommand) {
        log.debug "${device.displayName} - Parsed Crc16Encap into: ${encapsulatedCommand}"
        zwaveEvent(encapsulatedCommand)
    } else {
        log.warn "Could not extract crc16 command from $cmd"
    }
}

/**
 *  zwaveEvent( COMMAND_CLASS_CONFIGURATION V2 (0x70) : CONFIGURATION_REPORT (0x06) )
 *
 *  The Configuration Report Command is used to advertise the actual value of the advertised parameter.
 *
 *  Action: Store the value in the parameter cache, update syncPending, and log an info message.
 *
 *  Note: The Fibaro Flood Sensor documentation treats some parameter values as SIGNED and others as UNSIGNED!
 *   configurationValues are converted accordingly, using the isSigned attribute from getParamMd().
 *
 *  Note: Ideally, we want to update the corresponding preference value shown on the Settings GUI, however this
 *  is not possible due to security restrictions in the SmartThings platform.
 *
 *  cmd attributes:
 *    List<Short>  configurationValue        Value of parameter (byte array).
 *    Short        parameterNumber           Parameter ID.
 *    Integer      scaledConfigurationValue  Value of parameter (as signed int).
 *    Short        size                      Size of parameter's value (bytes).
 *
 *  Example: ConfigurationReport(configurationValue: [0], parameterNumber: 14, reserved11: 0,
 *            scaledConfigurationValue: 0, size: 1)
 **/
def zwaveEvent(hubitat.zwave.commands.configurationv2.ConfigurationReport cmd) {
    logger("zwaveEvent(): Configuration Report received: ${cmd}","trace")

    def paramMd = parameterMap().find( { it.id == cmd.parameterNumber })
    def paramValue = cmd.scaledConfigurationValue

    state."paramCache${cmd.parameterNumber}" = paramValue
    logger("Parameter #${cmd.parameterNumber} [${paramMd?.title}] has value: ${paramValue}","info")
    updateSyncPending()
}

/**
 *  zwaveEvent( COMMAND_CLASS_NOTIFICATION V3 (0x71) : NOTIFICATION_REPORT (0x05) )
 *
 *  The Notification Report Command is used to advertise notification information.
 *
 *  Action: Raise appropriate type of event (e.g. fault, tamper, contact) and log an info or warn message.
 *
 *  cmd attributes:
 *    Short        event                  Event Type (see code below).
 *    List<Short>  eventParameter         Event Parameter(s) (depends on Event type).
 *    Short        eventParametersLength  Length of eventParameter.
 *    Short        notificationStatus     The notification reporting status of the device (depends on push or pull model).
 *    Short        notificationType       Notification Type (see code below).
 *    Boolean      sequence
 *    Short        v1AlarmLevel           Legacy Alarm Level from Alarm CC V1.
 *    Short        v1AlarmType            Legacy Alarm Type from Alarm CC V1.
 *    Short        zensorNetSourceNodeId  Source node ID
 *
 *  Example: NotificationReport(event: 8, eventParameter: [], eventParametersLength: 0, notificationStatus: 255,
 *    notificationType: 8, reserved61: 0, sequence: false, v1AlarmLevel: 0, v1AlarmType: 0, zensorNetSourceNodeId: 0)
 **/
def zwaveEvent(hubitat.zwave.commands.notificationv3.NotificationReport cmd) {
    logger("zwaveEvent(): Notification Report received: ${cmd}","trace")

    def result = []

    switch (cmd.notificationType) {
        case 6:
            switch (cmd.event) {
                case 22:
                    result << createEvent(name: "contact", value: "open", descriptionText: "contact is open", displayed: true)
                    logger("contact is open","info")
                    break
                case 23:
                    result << createEvent(name: "contact", value: "closed", descriptionText: "contact is closed", displayed: true)
                    logger("contact is closed","info")
                    break
            }

            if (cmd.event == 22) { multiStatusEvent("Contact Open - $lastTime") }
            break;
        case 7:
            switch (cmd.event) {
                case 0:
                    result << createEvent(name: "tamper", value: "detected", descriptionText: "tamper cleared", displayed: true)
                    logger("tamper cleared","info")
                    break
                case 3:
                    result << createEvent(name: "tamper", value: "detected", descriptionText: "tamper detected", displayed: true)
                    logger("tamper detected","warn")
                    break
            }
            if (cmd.event == 3) { multiStatusEvent("Tamper - $lastTime") }
            break;
        case 4:
            if (device.currentValue("temperatureAlarm")?.value != null) {
                switch (cmd.event) {
                    case 0: sendEvent(name: "temperatureAlarm", value: "clear"); break;
                    case 2: sendEvent(name: "temperatureAlarm", value: "overheat"); break;
                    case 6: sendEvent(name: "temperatureAlarm", value: "underheat"); break;
                };
            };
            break;
        default: log.warn "${device.displayName} - Unknown notificationType: ${cmd.notificationType}";
    }

    return result
}

/**
 *  zwaveEvent( COMMAND_CLASS_MANUFACTURER_SPECIFIC V2 (0x72) : MANUFACTURER_SPECIFIC_REPORT (0x05) )
 *
 *  Manufacturer-Specific Reports are used to advertise manufacturer-specific information, such as product number
 *  and serial number.
 *
 *  Action: Publish values as device 'data'. Log a warn message if manufacturerId and/or productId do not
 *  correspond to Fibaro Door/Window Sensor V1.
 *
 *  Example: ManufacturerSpecificReport(manufacturerId: 271, manufacturerName: Fibargroup, productId: 4097,
 *   productTypeId: 2816)
 **/
def zwaveEvent(hubitat.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport cmd) {
    logger("zwaveEvent(): Manufacturer-Specific Report received: ${cmd}","trace")

    // Display as hex strings:
    def manufacturerIdDisp = String.format("%04X",cmd.manufacturerId)
    def productIdDisp = String.format("%04X",cmd.productId)
    def productTypeIdDisp = String.format("%04X",cmd.productTypeId)

    logger("Manufacturer-Specific Report: Manufacturer ID: ${manufacturerIdDisp}, Manufacturer Name: ${cmd.manufacturerName}" +
    ", Product Type ID: ${productTypeIdDisp}, Product ID: ${productIdDisp}","info")

    if ( 271 != cmd.manufacturerId) logger("Device Manufacturer is not Fibaro. Using this device handler with a different device may damage your device!","warn")
    if ( 4097 != cmd.productId) logger("Product ID does not match Fibaro Door/Window Sensor. Using this device handler with a different device may damage you device!","warn")

    updateDataValue("manufacturerName",cmd.manufacturerName)
    updateDataValue("manufacturerId",manufacturerIdDisp)
    updateDataValue("productId",productIdDisp)
    updateDataValue("productTypeId",productTypeIdDisp)
}

/**
 *  zwaveEvent( COMMAND_CLASS_FIRMWARE_UPDATE_MD V2 (0x7A) : FIRMWARE_MD_REPORT (0x02) )
 *
 *  The Firmware Meta Data Report Command is used to advertise the status of the current firmware in the device.
 *
 *  Action: Publish values as device 'data' and log an info message. No check is performed.
 *
 *  cmd attributes:
 *    Integer  checksum        Checksum of the firmware image.
 *    Integer  firmwareId      Firware ID (this is not the firmware version).
 *    Integer  manufacturerId  Manufacturer ID.
 *
 *  Example: FirmwareMdReport(checksum: 50874, firmwareId: 274, manufacturerId: 271)
 **/
def zwaveEvent(hubitat.zwave.commands.firmwareupdatemdv2.FirmwareMdReport cmd) {
    logger("zwaveEvent(): Firmware Metadata Report received: ${cmd}","trace")

    // Display as hex strings:
    def firmwareIdDisp = String.format("%04X",cmd.firmwareId)
    def checksumDisp = String.format("%04X",cmd.checksum)

    logger("Firmware Metadata Report: Firmware ID: ${firmwareIdDisp}, Checksum: ${checksumDisp}","info")

    updateDataValue("firmwareId","${firmwareIdDisp}")
    updateDataValue("firmwareChecksum","${checksumDisp}")
}

/**
 *  zwaveEvent( COMMAND_CLASS_BATTERY V1 (0x80) : BATTERY_REPORT (0x03) )
 *
 *  The Battery Report command is used to report the battery level of a battery operated device.
 *
 *  Action: Raise battery event and log an info message.
 *
 *  cmd attributes:
 *    Integer  batteryLevel  Battery level (%).
 *
 *  Example: BatteryReport(batteryLevel: 52)
 **/
def zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd) {
    logger("zwaveEvent(): Battery Report received: ${cmd}","trace")
    logger("Battery Level: ${cmd.batteryLevel}%","info")

    def result = []
    result << createEvent(name: "battery", value: cmd.batteryLevel, unit: "%", displayed: true)
    result << createEvent(name: "batteryStatus", value: "Battery: ${cmd.batteryLevel}%", displayed: false)

    return result
}

/**
 *  zwaveEvent( COMMAND_CLASS_WAKE_UP V1 (0x84) : WAKE_UP_INTERVAL_REPORT (0x06) )
 *
 *  The Wake Up Interval Report command is used to report the wake up interval of a device and the NodeID of the
 *  device receiving the Wake Up Notification Command.
 *
 *  Action: cache value, update syncPending, and log info message.
 *
 *  cmd attributes:
 *    nodeid
 *    seconds
 *
 *  Example: WakeUpIntervalReport(nodeid: 1, seconds: 300)
 **/
def zwaveEvent(hubitat.zwave.commands.wakeupv1.WakeUpIntervalReport cmd) {
    logger("zwaveEvent(): Wakeup Interval Report received: ${cmd}","trace")

    state.wakeUpIntervalCache = cmd.seconds.toInteger()
    logger("Wake Up Interval is ${cmd.seconds} seconds.","info")
    updateSyncPending()
}

/**
 *  zwaveEvent( COMMAND_CLASS_WAKE_UP V1 (0x84) : WAKE_UP_NOTIFICATION (0x07) )
 *
 *  The Wake Up Notificaiton command allows a battery-powered device to notify another device that it is awake and
 *  ready to receive any queued commands.
 *
 *  TODO: Action: Request BatteryReport, FirmwareMdReport, ManufacturerSpecificReport, and VersionReport.
 *
 *  cmd attributes:
 *    None
 *
 *  Example: WakeUpNotification()
 **/
def zwaveEvent(hubitat.zwave.commands.wakeupv2.WakeUpNotification cmd) {
    logger("zwaveEvent(): Wakeup Notification received: ${cmd}","trace")

    logger("Device Woke Up","info")

    def result = []

    result << response(zwave.batteryV1.batteryGet())
    result << response(zwave.firmwareUpdateMdV2.firmwareMdGet())
    result << response(zwave.manufacturerSpecificV2.manufacturerSpecificGet())
    result << response(zwave.versionV1.versionGet())

    // Send wakeUpNoMoreInformation command, but only if there is nothing more to sync:
    if (device.latestValue("syncPending").toInteger() == 0) result << response(zwave.wakeUpV1.wakeUpNoMoreInformation())

    return result
}

/**
 *  zwaveEvent( COMMAND_CLASS_VERSION V1 (0x86) : VERSION_REPORT (0x12) )
 *
 *  The Version Report Command is used to advertise the library type, protocol version, and application version.

 *  Action: Publish values as device 'data' and log an info message. No check is performed.
 *
 *  Note: Device actually supports V2, but SmartThings only supports V1.
 *
 *  cmd attributes:
 *    Short  applicationSubVersion
 *    Short  applicationVersion
 *    Short  zWaveLibraryType
 *    Short  zWaveProtocolSubVersion
 *    Short  zWaveProtocolVersion
 *
 *  Example: VersionReport(applicationSubVersion: 4, applicationVersion: 3, zWaveLibraryType: 3,
 *   zWaveProtocolSubVersion: 5, zWaveProtocolVersion: 4)
 **/
def zwaveEvent(hubitat.zwave.commands.versionv1.VersionReport cmd) {
    logger("zwaveEvent(): Version Report received: ${cmd}","trace")

    def zWaveLibraryTypeDisp  = String.format("%02X",cmd.zWaveLibraryType)
    def zWaveLibraryTypeDesc  = ""
    switch(cmd.zWaveLibraryType) {
        case 3:
            zWaveLibraryTypeDesc = "Enhanced Slave"
            break

        default:
            zWaveLibraryTypeDesc = "N/A"
    }

    def applicationVersionDisp = String.format("%d.%02d",cmd.applicationVersion,cmd.applicationSubVersion)
    def zWaveProtocolVersionDisp = String.format("%d.%02d",cmd.zWaveProtocolVersion,cmd.zWaveProtocolSubVersion)

    logger("Version Report: Application Version: ${applicationVersionDisp}, " +
           "Z-Wave Protocol Version: ${zWaveProtocolVersionDisp}, " +
           "Z-Wave Library Type: ${zWaveLibraryTypeDisp} (${zWaveLibraryTypeDesc})","info")

    updateDataValue("applicationVersion","${cmd.applicationVersion}")
    updateDataValue("applicationSubVersion","${cmd.applicationSubVersion}")
    updateDataValue("zWaveLibraryType","${zWaveLibraryTypeDisp}")
    updateDataValue("zWaveProtocolVersion","${cmd.zWaveProtocolVersion}")
    updateDataValue("zWaveProtocolSubVersion","${cmd.zWaveProtocolSubVersion}")
}


private multiStatusEvent(String statusValue, boolean force = false, boolean display = false) {
    if (!device.currentValue("multiStatus")?.contains("Sync") || device.currentValue("multiStatus") == "Sync OK." || force) {
        sendEvent(name: "multiStatus", value: statusValue, descriptionText: statusValue, displayed: display)
    }
}


//from: https://raw.githubusercontent.com/garyd9/smartthings/master/my_z-wave_garage_door_opener.groovy
def zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationBusy cmd) {
	def msg = cmd.status == 0 ? "try again later" :
	          cmd.status == 1 ? "try again in $cmd.waitTime seconds" :
	          cmd.status == 2 ? "request queued" : "sorry"
	createEvent(displayed: true, descriptionText: "$device.displayName is busy, $msg")
}

def zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationRejectedRequest cmd) {
    log.warn "${device.displayName} - rejected request!"
    for ( param in parameterMap() ) {
        if ( state."paramTarget${param.id}"?.state == "inProgress" ) {
            state."paramTarget${param.id}"?.state = "failed"
            break
        }
    }
}



def zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
    def encapsulatedCommand = cmd.encapsulatedCommand(cmdVersions())
    if (encapsulatedCommand) {
        log.debug "${device.displayName} - Parsed SecurityMessageEncapsulation into: ${encapsulatedCommand}"
        zwaveEvent(encapsulatedCommand)
    } else {
        log.warn "Unable to extract secure cmd from $cmd"
    }
}

/**
 *  zwaveEvent( DEFAULT CATCHALL )
 *
 *  Called for all commands that aren't handled above.
 **/
def zwaveEvent(hubitat.zwave.Command cmd) {
    logger("zwaveEvent(): No handler for command: ${cmd}","error")
}

/*****************************************************************************************************************
 *  Hubitat System Commands:
 *****************************************************************************************************************/

/**
 *  installed()
 *
 *  Runs when the device is first installed.
 *
 *  Action: Set initial values for internal state.
 **/
def installed() {
    log.trace "installed()"

    state.loggingLevelIDE     = 5
    state.loggingLevelDevice  = 2

    // Initial settings:
    logger("Performing initial setup","info")

    state.wakeUpIntervalTarget = 300

    sync()

    // Request extra info (same as wakeup):
    List<hubitat.zwave.Command> cmds = []
    cmds << zwave.batteryV1.batteryGet()
    cmds << zwave.firmwareUpdateMdV2.firmwareMdGet()
    cmds << zwave.manufacturerSpecificV2.manufacturerSpecificGet()
    cmds << zwave.versionV1.versionGet()
    sendToDevice(cmds)

}

/**
 *  updated()
 *
 *  Runs when the user hits "Done" from Settings page.
 *
 *  Action: Process new settings, set targets for wakeup interval, parameters, and association groups (ready for next sync).
 *
 *  Note: Weirdly, update() seems to be called twice. So execution is aborted if there was a previous execution
 *  within two seconds. See: https://community.smartthings.com/t/updated-being-called-twice/62912
 **/
def updated() {
    logger("updated()","trace")

    if (!state.updatedLastRanAt || now() >= state.updatedLastRanAt + 2000) {
        state.updatedLastRanAt = now()

        // Update internal state:
        state.loggingLevelIDE       = (settings.configLoggingLevelIDE) ? settings.configLoggingLevelIDE.toInteger() : 3
        state.loggingLevelDevice    = (settings.configLoggingLevelDevice) ? settings.configLoggingLevelDevice.toInteger(): 2
        state.syncAll               = ("true" == settings.configSyncAll)

        // Update Wake Up Interval target:
        state.wakeUpIntervalTarget = (settings.configWakeUpInterval) ? settings.configWakeUpInterval.toInteger() : 3600

        // Update Parameter target values:
        parameterMap().findAll().each {
            state."paramTarget${it.id}" = settings."configParam${it.id}"?.toInteger()
        }

        if ( settings.temperatureHigh as Integer == 0 && settings.temperatureLow as Integer == 0 ) {
            sendEvent(name: "temperatureAlarm", value: null, displayed: false)
        } else if ( settings.temperatureHigh != null || settings.temperatureHigh != null ) {
            sendEvent(name: "temperatureAlarm", value: "clear", displayed: false)
        }

        updateSyncPending()

    }
    else {
        logger("updated(): Ran within last 2 seconds so aborting.","debug")
    }
}

/*****************************************************************************************************************
 *  Private Helper Functions:
 *****************************************************************************************************************/

/**
 *  logger()
 *
 *  Wrapper function for all logging:
 *    Logs messages to the IDE (Live Logging), and also keeps a historical log of critical error and warning
 *    messages by sending events for the device's logMessage attribute.
 *    Configured using configLoggingLevelIDE and configLoggingLevelDevice preferences.
 **/
private logger(msg, level = "debug") {

    switch(level) {
        case "error":
            if (state.loggingLevelIDE >= 1) log.error msg
            if (state.loggingLevelDevice >= 1) sendEvent(name: "logMessage", value: "ERROR: ${msg}", displayed: false, isStateChange: true)
            break

        case "warn":
            if (state.loggingLevelIDE >= 2) log.warn msg
            if (state.loggingLevelDevice >= 2) sendEvent(name: "logMessage", value: "WARNING: ${msg}", displayed: false, isStateChange: true)
            break

        case "info":
            if (state.loggingLevelIDE >= 3) log.info msg
            break

        case "debug":
            if (state.loggingLevelIDE >= 4) log.debug msg
            break

        case "trace":
            if (state.loggingLevelIDE >= 5) log.trace msg
            break

        default:
            log.debug msg
            break
    }
}

/**
 *  sync()
 *
 *  Manages synchronisation of parameters, association groups, and wake up interval with the physical device.
 *  The syncPending attribute advertises remaining number of sync operations.
 *
 *  Does not return a list of commands, it sends them immediately using sendSequence().
 *
 *  Parameters:
 *   forceAll    Force all items to be synced, otherwise only changed items will be synced.
 **/
private sync(forceAll = false) {
    logger("sync(): Syncing configuration with the physical device.","info")

    def cmds = []
    def syncPending = 0

    if (state.syncAll) { // Clear all cached values.
        state.wakeUpIntervalCache = null
        parameterMap().findAll().each { state."paramCache${it.id}" = null }
        state.syncAll = false
    }

    if ( (state.wakeUpIntervalTarget != null) & (state.wakeUpIntervalTarget != state.wakeUpIntervalCache)) {
        cmds << zwave.wakeUpV1.wakeUpIntervalSet(seconds: state.wakeUpIntervalTarget, nodeid: zwaveHubNodeId)
        cmds << zwave.wakeUpV1.wakeUpIntervalGet().format()
        logger("sync(): Syncing Wake Up Interval: New Value: ${state.wakeUpIntervalTarget}","info")
        syncPending++
    }

    parameterMap().findAll().each { // Exclude readonly parameters.
        if ( (state."paramTarget${it.id}" != null) & (state."paramCache${it.id}" != state."paramTarget${it.id}") ) {
            // configurationSet will detect if scaledConfigurationValue is SIGNEd or UNSIGNED and convert accordingly:
            cmds << zwave.configurationV2.configurationSet(parameterNumber: it.id, size: it.size, scaledConfigurationValue: state."paramTarget${it.id}".toInteger())
            cmds << zwave.configurationV2.configurationGet(parameterNumber: it.id)
            logger("sync(): Syncing parameter #${it.id} [${it.name}]: New Value: " + state."paramTarget${it.id}","info")
            syncPending++
        }
    }

    sendEvent(name: "syncPending", value: syncPending, displayed: false)
    if (cmds) {
        // naive prevention of dev:4612022-01-14 18:04:46.068 errorjava.lang.ArrayIndexOutOfBoundsException: -1 on line 856 (method parse)
        sendToDevice(cmds)
    } else {
        logger("sync(): Configuration was already synced.","info")
    }
}

/**
 *  updateSyncPending()
 *
 *  Updates syncPending attribute, which advertises remaining number of sync operations.
 **/
private updateSyncPending() {

    def syncPending = 0

    if ( (state.wakeUpIntervalTarget != null) & (state.wakeUpIntervalTarget != state.wakeUpIntervalCache)) {
        syncPending++
    }

    parameterMap().findAll().each {
        if ( (state."paramTarget${it.id}" != null) & (state."paramCache${it.id}" != state."paramTarget${it.id}") ) {
            syncPending++
        }
    }

    logger("updateSyncPending(): syncPending: ${syncPending}", "debug")
    if ((syncPending == 0) & (device.latestValue("syncPending") > 0)) logger("Sync Complete.", "info")
    sendEvent(name: "syncPending", value: syncPending, displayed: false)
}

/*****************************************************************************************************************
 *  Code from this point comes from https://github.com/djdizzyd/hubitat/ by Bryan Copeland (djdizzyd).
 *****************************************************************************************************************/

void sendToDevice(List<hubitat.zwave.Command> cmds) {
    sendHubCommand(new hubitat.device.HubMultiAction(commands(cmds), hubitat.device.Protocol.ZWAVE))

}

void sendToDevice(hubitat.zwave.Command cmd) {
    sendHubCommand(new hubitat.device.HubAction(secureCommand(cmd), hubitat.device.Protocol.ZWAVE))
}

void sendToDevice(String cmd) {
    sendHubCommand(new hubitat.device.HubAction(secureCommand(cmd), hubitat.device.Protocol.ZWAVE))
}

List<String> commands(List<hubitat.zwave.Command> cmds, Long delay=200) {
    return delayBetween(cmds.collect{ secureCommand(it) }, delay)
}

String secureCommand(hubitat.zwave.Command cmd) {
    secureCommand(cmd.format())
}

String secureCommand(String cmd) {
    String encap=""
    if (getDataValue("zwaveSecurePairingComplete") != "true") {
        return cmd
    } else {
        encap = "988100"
    }
    return "${encap}${cmd}"
}
/*****************************************************************************************************************
 *  Code until this point comes from https://github.com/djdizzyd/hubitat/ by Bryan Copeland (djdizzyd).
 *****************************************************************************************************************/

/*****************************************************************************************************************
 *  Static Matadata Functions:
 *
 *  These functions encapsulate metadata about the device. Mostly obtained from:
 *   Z-wave Alliance Reference:
 *   - https://products.z-wavealliance.org/products/1356 Product Version: 02, Product Type ID: 0x0702
 *   - https://products.z-wavealliance.org/products/1050 Product Version: 2.5, Product Type ID: 0x0700

 *****************************************************************************************************************/

private Map cmdVersions() {
    return [0x20: 1, // Basic V1
            0x30: 2, // Sensor Binary V2
            0x31: 5, // Sensor Multilevel V5
            0x56: 1, // CRC16 Encapsulation V1
            0x60: 3, // Multi Channel V3
            0x70: 2, // Configuration V2
            0x72: 2, // Manufacturer Specific V2
            0x7A: 2, // Firmware Update MD V2
            0x80: 1, // Battery V1
            0x84: 2, // Wake Up V2
            0x85: 2, // Association V2
            0x86: 1, // Version V1
            0x9C: 1  // Sensor Alarm V1
    ]
}

private parameterMap() {[
        [id: 1, size: 1, type: "enum", options: [0: "Door/Window Sensor or external alarm sensor", 1: "external button"], def: "0", title: "Operation mode", descr: "Parameter defines device operation mode."],
        [id: 2, size: 1, type: "enum", options: [0: "door/window closed", 1: "door/window opened"], def: "0", title: "Door/Window or alarm status", descr: "Parameter defines state of the sensor when the magnet is close. If the alarm sensor is connected, it determines the output type. Parameter inactive in external button mode (parameter 1 set to 1)."],
        [id: 3, size: 1, type: "enum", options: [
                0: "No indications",
                1: "Indication of opening/closing status change (input IN)",
                2: "Indication of wake up (1 x click or periodical)",
                3: "Indication of opening/closing status change (input IN) & wake up (1 x click or periodical)",
                4: "Indication of device tampering",
                5: "Indication of wake up (1 x click or periodical) & opening/closing status change (input IN) & wake up (1 x click or periodical)",
                6: "Indication of wake up & tampering",
        ],
         def: "6", title: "Visual LED indications",
         descr: "This parameter defines events indicated by the visual LED indicator. Disabling events might extend battery life."],
        [id: 4, size: 1, type: "enum", options: [
                0: "Disabled",
                1: "Enabled",
        ],
         def: "0", title: "Range test after double click",
         descr: "Allows to enable activation of Z-Wave range test with double click of a TMP button."],
        [id: 30, size: 2, type: "number", def: 5, min: 0, max: 32400, title: "Tamper - alarm cancellation delay",
         descr: "Time period after which a tamper alarm will be cancelled.\n0-32400 - time in seconds"],
        [id: 31, size: 1, type: "enum", options: [
				0: "Do not send tamper cancellation report",
				1: "Send tamper cancellation report"
		],
		 def: "1", title: "Reporting tamper alarm cancellation",
         descr: "Reporting cancellation of tamper alarm to the controller and 5th associationgroup."],
        [id: 50, size: 2, type: "number", def: 300, min: 0, max: 32400, title: "Interval of temperature measurements",
         descr: "This parameter defines how often the temperature will be measured (specific time).\n0 - temperature measurements disabled\n5-32400 - time in seconds"],
        [id: 51, size: 2, type: "enum", options: [
                0: "disabled",
                3: "0.5°F/0.3°C",
                6: "1°F/0.6°C",
                11: "2°F/1.1°C",
                17: "3°F/1.7°C",
                22: "4°F/2.2°C",
                28: "5°F/2.8°C"],
         def: 11, title: "Temperature reports threshold",
         descr: "Change of temperature resulting in temperature report being sent to the HUB."],
        [id: 54, size: 1, type: "enum", options: [
                0: "Temperature alarms disabled",
                1: "High temperature alarm",
                2: "Low temperature alarm",
                3: "High and low temperature alarms"],
         def: "0", title: "Temperature alarm reports",
         descr: "Temperature alarms reported to the Z-Wave controller. Thresholds are set in parameters 55 and 56"],
        [id: 55, size: 2, type: "enum", options: [
                0: "disabled",
                200: "68°F/20°C",
                250: "77°F/25°C",
                300: "86°F/30°C",
                350: "95°F/35°C",
                400: "104°F/40°C",
                450: "113°F/45°C",
                500: "122°F/50°C",
                550: "131°F/55°C",
                600: "140°F/60°C"],
         def: 350, title: "High temperature alarm threshold",
         descr: "If temperature is higher than set value, overheat high temperature alarm will be triggered."],
        [id: 56, size: 2, type: "enum", options: [
                0: "disabled",
                6: "33°F/0.6°C",
                10: "34°F/1°C",
                22: "36°F/2.2°C",
                33: "38°F/3.3°C",
                44: "40°F/4.4°C",
                50: "41°F/5°C",
                100: "50°F/10°C",
                150: "59°F/15°C",
                200: "68°F/20°C",
                250: "77°F/25°C"],
         def: 100, title: "Low temperature alarm threshold",
         descr: "If temperature is lower than set value, low temperature alarm will be triggered."]
]
}

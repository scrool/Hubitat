/**
 *  Fibaro Z-Wave FGK-101 Temperature & Door/Window Sensor Handler [v0.9.7.4.7]
 *		
 *  Copyright 2014 Jean-Jacques GUILLEMAUD
 *  Copyright 2021 Pavol Babinčák
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */
 
/******************************************************************************************************************************
/* IMPORTANT : This custom Handler works both for Z-Wave+ (aka ZW5) versions of the FGK-101 Fibaro sensor,
/*             as well as for pre-ZW5 versions of the FGK-101 hardware.
/*             It takes about 1mn for the FGK-101 to fully configure itself after the first (manual or otherwise) wakeup.
/******************************************************************************************************************************
 *	Fibaro Z-Wave FGK-101 Marketing Description is at :
 *		http://www.fibaro.com/en/the-fibaro-system/door-window-sensor
 *
 *  Fibaro FGK-10x Operating Manuals and Z-Wave Alliance Certificates can be downloaded at :
 *		Z-Wave / Firmware <= 2.5 		: http://www.fibaro.com/files/instrukcje/eng/DoorWindowSensor%20FGK-101-107%20ENG_v21-v23.pdf
 *										: http://products.z-wavealliance.org/products/1077
 *		Z-Wave+ / ZW5 / Firmware >= 3.2 : http://manuals.fibaro.com/content/manuals/en/FGK-10x/FGK-10x-EN-T-v2.0.pdf
 *										: http://products.z-wavealliance.org/products/1620
 *
 *	The current version of this Handler is parameterized to force Device's wakeup :
 *		- on any open<->closed state change
 *		- in case of Tampering Alarm triggering
 *		- every 60mn (wakeUpIntervalSet(seconds:60*60), hard coded)
 *		- whenever Temperature delta change since last report is greater than 0.3°C (Parameter#12 or #51, hard coded)
 *		- every 4h when Temperature does not change
 *		also :
 *		- Temperature is natively reported by sensor in Celsius (SensorMultilevelReport[scale:0]);
 *		  convertion is needed for Fahrenheit display 
 *
 *  A few specificities of this device that are relevant to better understand some parts of this Handler :
 *		- it is a battery operated device, so Commands can only be sent to it whenever it wakes up
 *		- it is a multi-channel Device (pre-ZW5), and the multi-level temperature sensor reports only from EndPoint#2
 *		- specific configurable parameters are documented in the above Operating Manuals
 *		- some of those parameters must be modified to activate the anti-Tampering Alarm
 *		- some of the "scaffolding" has been left in place as comments, since it may help other people to understand/modify this Handler
 *		- BEWARE : the optional DS18B20 temperature sensor must be connected BEFORE the Device is activated (otherwise, reset the Device)
 *		- IMPORTANT : for debugging purpose, it is much better to change the wake-up period from the default 60mn to 1mn or so;
 *					but unless you force the early wake up of the sensor (forcing open/closed for instance), you will have to
 *					wait up to 60mn for the new value to become effective.
 *
 * Z-Wave Device Class: GENERIC_TYPE_SENSOR_BINARY / SPECIFIC_TYPE_ROUTING_SENSOR_BINARY
 * FGK-101 Raw Description [EndPoint:0] : "0 0 0x2001 0 0 0 c 0x30 0x9C 0x60 0x85 0x72 0x70 0x86 0x80 0x84 0x7A 0xEF 0x2B"
 * Command Classes supported according to Z-Wave Certificate ZC08-14070004 for FGK-101\US :
 * 	 Used in Handler (pre-ZW5 and ZW5) :
 *		0x20 - 32  : BASIC					V1
 *		0x30 - 48  : SENSOR_BINARY			V2
 *		0x31 - 49  : SENSOR_MULTILEVEL		V5
 *		0x56 - 86  : CRC_16_ENCAP			V1
 *		0x70 - 112 : CONFIGURATION			V2
 *		0x80 - 128 : BATTERY				V1
 *		0x84 - 132 : WAKE_UP				V2
 *		0x85 - 133 : ASSOCIATION			V2
 *		0x86 - 134 : VERSION				V1
 *		0x9C - 156 : SENSOR_ALARM			V1
 * 	 Used in Handler (pre-ZW5 only) :
 *		0x60 - 96  : MULTI_CHANNEL			V3
 * 	 Used in Handler (ZW5 only) :
 *		0x71 - 113 : NOTIFICATION			V3	
 *		0x98 - 152 : SECURITY				V1
 ******************************************************************************************************************************/

/******************************************************************************************************************************
 *	List of Known Bugs / Oddities / Missing Features :
 *		- valueTitle does not show displayNames on mobile Dashboard/Things page;
 *		  attempted workaround using : valueTile(){unit:'${displayName}') failed
 *		- valueTile behaves differently on mobile Dashboard (interpolated colors) from Simulator (step-wise colors)
 *		- using Preferences values instead of hard-coded values for some parameters would be nicer
 *		- ZW5 : Sensor Multilevel Report() received in answer to Sensor Multilevel Get() is buggy (+/- 1°C random error)
 *****************************************************************************************************************************/

metadata {
	definition (name: "Fibaro Door/Window sensor FGK-10x", namespace: "scrool", author: "Pavol Babinčák", importUrl: "https://raw.githubusercontent.com/scrool/Hubitat/master/Hubitat/Drivers/fibaro-door-window-sensor-fgk-10x.src/fibaro-door-window-sensor-fgk-10x.groovy") {
		capability "Contact Sensor"
		capability "Battery"
		capability "Configuration"
		capability "Temperature Measurement"
		capability "Sensor"
		capability "Tamper Alert"
        
        command "reportNext", ["string"]
        
        // Use Device Custom Attributes whenever state.xxx Attributes are too vulnerable to race conditions
        attribute "reportASAP", "number"
        attribute "forcedWakeUp", "number"
        attribute "ZW5set", "number"
        attribute "ZW5", "number"
        attribute "Configured", "number"

        fingerprint mfr: "010F", deviceId: "1001"

        //https://products.z-wavealliance.org/products/1050?selectedFrequencyId=1
        fingerprint deviceType: "0700", inClusters: "0x5E,0x85,0x59,0x22,0x20,0x80,0x70,0x56,0x5A,0x7A,0x72,0x8E,0x71,0x73,0x98,0x2B,0x9C,0x30,0x31,0x86,0x84", deviceJoinName: "Fibaro FGK-10x with temperature sensor"
        fingerprint deviceType: "0701", inClusters: "0x5E,0x85,0x59,0x22,0x20,0x80,0x70,0x56,0x5A,0x7A,0x72,0x8E,0x71,0x73,0x98,0x2B,0x9C,0x30,0x86,0x84", deviceJoinName: "Fibaro FGK-10x"
	}

	simulator {
		status "open":  "command: 2001, payload: FF"
		status "closed": "command: 2001, payload: 00"

        def T_values=[10,14,14.9,15,17,17.9,18,19,19.9,20,22,22.9,23,24,44,44.9,45,46,100]
        def float Ti
        for (int i = 0; i <= T_values.size()-1; i += 1) {
            Ti=T_values.get(i)
        	def theSensorValue = [(short)0, (short)0, (short)(Ti*100)/256, (short)(Ti*100)%256]
			// status "temperature ${Ti}°C":  zwave.multiChannelV3.multiChannelCmdEncap(sourceEndPoint:2, destinationEndPoint:2).encapsulate(zwave.sensorMultilevelV5.sensorMultilevelReport(scaledSensorValue: i, precision: 2, scale: 0, sensorType: 1, sensorValue: theSensorValue, size:4)).incomingMessage()
        }
	}

	tiles { 
    	valueTile("temperature", "device.temperature", inactiveLabel: false, width: 2, height: 2, canChangeIcon: true, canChangeBackground: true) {
        	// label:'${name}', label:'${currentValue}', unit:"XXX" work, but NOT label:'${device.name}', label:'${displayName}', unit:'${unit}', ...
			state "temperature", label:'${currentValue}°\n', unit:"C", icon: "st.alarm.temperature.normal",
			// redondant lines added to avoid color interpolation on Dashboard (a feature or a bug ?!)
            backgroundColors:[							// ***on IDE Simulator***		// ***on iPad App***
				[value: 14, color: "#0033ff"],			//     °C <=14 : dark blue		//     °C <=14	: dark blue 
				    //[value: 14.1, color: "#00ccff"],	<- decimal value IGNORED by the Tile !!!
					//[value: 14.5],					// 15< °C <=19 : light blue		// 14< °C <15	: interpolated dark blue<-> light blue
                    [value: 15, color: "#00ccff"],		// 16< °C <=19 : light blue		// 15<=°C <=19	: light blue
                [value: 17, color: "#00ccff"],			// 16< °C <=19 : light blue		// 15<=°C <=19	: light blue
					//[value: 17.5],					// 15< °C <=19 : light blue		// 14< °C <15	: interpolated light blue<->blue-green
                	[value: 18, color: "#ccffcc"],		// 15< °C <=19 : light blue		// 18<=°C <=19	: blue-green
				[value: 19, color: "#ccffcc"],			// 15< °C <=19 : light blue		// 19°C			: blue-green
                    //[value: 19.5],					// 19< °C <=21 : blue-green		// 19< °C <20	: interpolated blue-green<->green
                	[value: 20, color: "#ccff00"],		// 19< °C <=21 : blue-green		// 20<=°C <=21	: green
				[value: 22, color: "#ccff00"],			// 21< °C <=23 : green			// 22°C			: green
					//[value: 22.5],					// 23< °C <=45 : orange			// 22< °C <23	: interpolated green<-> orange
					[value: 23, color: "#ffcc33"],		// 23< °C <=45 : orange  		// 23<=°C <=44	: orange
				[value: 43, color: "#ffcc33"],			// 23< °C <=45 : orange  		// 44°C			: orange
					//[value: 43.5],					// 45< °C      : red			// 44< °C <45	: interpolated orange <-> red
               		[value: 44, color: "#ff3300"]		// 45< °C      : red  			// 45<=°C		: red
			]
		}
  /*      
        valueTile("temperatureF", "device.temperature", inactiveLabel: false, width: 2, height: 2, canChangeIcon: true, canChangeBackground: true) {
        	// label:'${name}', label:'${currentValue}', unit:"XXX" work, but NOT label:'${device.name}', label:'${displayName}', unit:'${unit}', ...
			state "temperature", label:'${currentValue}°\n', unit:"F", icon: "st.alarm.temperature.normal",
			// redondant lines added to avoid color interpolation on Dashboard (a feature or a bug ?!)
            backgroundColors:[							// ***on IDE Simulator***		// ***on iPad App***
				[value: 57, color: "#0033ff"],			//     °C <=14 : dark blue		//     °C <=14	: dark blue 
				    //[value: 14.1, color: "#00ccff"],	<- decimal value IGNORED by the Tile !!!
					//[value: 14.5],					// 15< °C <=19 : light blue		// 14< °C <15	: interpolated dark blue<-> light blue
                    [value: 59, color: "#00ccff"],		// 16< °C <=19 : light blue		// 15<=°C <=19	: light blue
                [value: 63, color: "#00ccff"],			// 16< °C <=19 : light blue		// 15<=°C <=19	: light blue
					//[value: 17.5],					// 15< °C <=19 : light blue		// 14< °C <15	: interpolated light blue<->blue-green
                	[value: 64, color: "#ccffcc"],		// 15< °C <=19 : light blue		// 18<=°C <=19	: blue-green
				[value: 66, color: "#ccffcc"],			// 15< °C <=19 : light blue		// 19°C			: blue-green
                    //[value: 19.5],					// 19< °C <=21 : blue-green		// 19< °C <20	: interpolated blue-green<->green
                	[value: 68, color: "#ccff00"],		// 19< °C <=21 : blue-green		// 20<=°C <=21	: green
				[value: 72, color: "#ccff00"],			// 21< °C <=23 : green			// 22°C			: green
					//[value: 22.5],					// 23< °C <=45 : orange			// 22< °C <23	: interpolated green<-> orange
					[value: 73, color: "#ffcc33"],		// 23< °C <=45 : orange  		// 23<=°C <=44	: orange
				[value: 109, color: "#ffcc33"],			// 23< °C <=45 : orange  		// 44°C			: orange
					//[value: 43.5],					// 45< °C      : red			// 44< °C <45	: interpolated orange <-> red
               		[value: 111, color: "#ff3300"]		// 45< °C      : red  			// 45<=°C		: red
			]
		}
*/        
        standardTile("contact", "device.contact") {
			state "open", label: 'open'/* in English :'${name}' */, icon: "st.contact.contact.open", backgroundColor: "#ffa81e"
			state "closed", label: 'closed'/* in English :'${linkText}' */, icon: "st.contact.contact.closed", backgroundColor: "#79b821"
		}
        
        valueTile("battery", "device.battery", inactiveLabel: false, decoration: "flat") {
			state "battery", label:'batt. @ ${currentValue}%' /*battery*/, unit:""
		} 
        
        //Select temperatureF if Location temperature Scale is °F
        main(["temperature"])
		details(["temperature", "contact", "battery"])
        //main(["temperatureF"])
		//details(["temperatureF", "contact", "battery"])
	}
    preferences {
        input name: "debugLevel", type: "enum", title: "Debug level", options: [[0:"Disabled"],[1:"Level 1"],[2:"Level 2"]], defaultValue: 0
    }
}

////////////////////////////////
// parse events into attributes
////////////////////////////////

def parse(String description) {
		if (!state.parseCount) {
			if (debugLevel>=1) {
				log.debug "state.parseCount set to 0 in parse()"
			}
			state.parseCount=0
		} else {
			state.parseCount=state.parseCount+1
		}
		if (debugLevel>=1) {log.debug "--------------------------Parsing... ; state.parseCount: ${state.parseCount}--------------------------"}
		if (debugLevel>=2) {log.debug "Parsing... '${description}'"}
        def result = null
        def cmd = zwave.parse(description, [0x20:1, 0x30:2, 0x31:5, 0x56:1, 0x60:3, 0x70:2, 0x72:2, 0x80:1, 0x84:2, 0x85:2, 0x9C:1])
        if (cmd) {
                result = zwaveEvent(cmd)
                if (debugLevel>=1) {log.debug "Parsed ${cmd} to ${result.inspect()}"}
        } else {
                log.debug "Non-parsed event: ${description}"
        }
        return result
}


//SmartThings v2 Hub forces some CRC16-encoded replies from FGK-101 Device (v1 Hub did not)
def zwaveEvent(hubitat.zwave.commands.crc16encapv1.Crc16Encap cmd) {
	log.debug "CRC16.......... cmd : ${cmd}"
    def versions = [0x20:1, 0x30: 2, 0x31: 5, 0x60: 3, 0x70: 2, 0x72: 2, 0x80: 1, 0x84: 2, 0x86: 1, 0x9C: 1]
	// def encapsulatedCommand = cmd.encapsulatedCommand(versions)
	def version = versions[cmd.commandClass as Integer]
    log.debug "commandClass : ${cmd.commandClass}"
    log.debug "version : ${version}"
    log.debug "cmd.command : ${cmd.command}"
    log.debug "cmd.data : ${cmd.data}"
    def encapsulatedCommand = zwave.getCommand(cmd.commandClass, cmd.command, cmd.data, version)
    if (encapsulatedCommand) {
        zwaveEvent(encapsulatedCommand)
    } else {
        log.warn "Unable to extract CRC16 command from ${cmd}"
    }
}

// ZW5 Devices that support the Security command class can send messages in an
// encrypted form; they arrive wrapped within a SecurityMessageEncapsulation
// command and must be unencapsulated
def zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
		log.debug "cmd : ${cmd}"
        def encapsulatedCommand = cmd.encapsulatedCommand([0x20: 1, 0x30: 2, 0x70: 2, 0x71: 3, 0x84: 2, 0x85: 2, 0x98: 1, 0x9C: 1])
        // can specify command class versions here like in zwave.parse
        if (encapsulatedCommand) {
    			log.debug "ZW5 encapsulatedCommand : ${encapsulatedCommand}"
                return zwaveEvent(encapsulatedCommand)
        } else {
			log.warn "ZW5 Unable to extract encapsulated cmd from $cmd"
			createEvent(descriptionText: cmd.toString())
        }
}

def temperatureScaleFC(tempvalue) {
	//FGK-101 is natively °C; convert to °F if selected in Location settings
	def float tempFC = tempvalue
	if (location.temperatureScale == "F") {
		tempFC = tempvalue * 1.8 + 32
	}
	return tempFC
}

def wakeUpResponse(cmdBlock0) {
	def cmdBlock = []
	cmdBlock += cmdBlock0
	//Initialization... (executed only once, when the Handler has been updated)
    //All untouched parameters are supposed to be DEFAULT (as factory-set)
    if (debugLevel>=2) {log.debug "device.Configured : ${device.currentValue('Configured')}"}
    if (!(device.currentValue('Configured'))) {
		cmdBlock += configureDev()
		log.debug "++++++++returned cmdBlock : ${cmdBlock}"
	}
	//Regular ZW5 & non-ZW5 Commands...
    def long nowTime = new Date().getTime()
    log.debug "state.lastReportBattery : ${state.lastReportBattery}"
    if (state.batteryInterval) {
    	if (nowTime-state.lastReportBattery > state.batteryInterval) {
        	// batteryGet() should definitely NOT be CRC16 encoded ! [buggy ZW5 Fibaro handler !!]
			cmdBlock << zwave.batteryV1.batteryGet().format()
        	cmdBlock << "delay ${state.shortDelay}"
    	}
    }
    	//ZW5 : "wakeUpIntervalReport doesn’t work uint24FromBytes missing from response" : https://community.smartthings.com/t/wakeupintervalget-doesnt-work-uint24frombytes-missing-from-response/10577
    	//cmdBlock << encap(zwave.wakeUpV2.wakeUpIntervalGet()) // NB : may have to wait 60mn for that value to be refreshed !
    	//cmdBlock << "delay ${state.longDelay}"
    if (device.currentValue('ZW5set')) {
    	// DS18B20 temperature measurement at 12bits accuracy takes more than 750ms...
    	if (device.currentValue('ZW5')) {
        	// sensorMultilevelGet() should be +++PROPERLY+++ CRC16-encoded ! buggy ZW5 Fibaro handler w/ checksum = 0x0000 !!!
            // sensorMultilevelReport() synchronous answer to sensorMultilevelGet() is buggy for whatever reason (+/-1°C) => disable sensorMultilevelGet()
            //cmdBlock << crc16Encode(zwave.sensorMultilevelV5.sensorMultilevelGet(sensorType: 1, scale: 0))
			//cmdBlock << "delay ${state.longDelay}"
    	} else {
    		cmdBlock << zwave.multiChannelV3.multiChannelCmdEncap(sourceEndPoint: 2, destinationEndPoint: 2, commandClass:0x31, command:4).format()  //sensorMultiLevel.get()
            cmdBlock << "delay ${state.longDelay}"
    	}
    }
	cmdBlock << zwave.wakeUpV2.wakeUpNoMoreInformation().format()
    if (debugLevel>=2) {
        log.debug "wakeUpNoMoreInformation()"
        log.debug "cmdBlock : ${cmdBlock}"
    }
    return cmdBlock
}

def zwaveEvent(hubitat.zwave.commands.wakeupv2.WakeUpNotification cmd) {
		// IMPORTANT NOTE : when the batteryLevel becomes too low, Device reports become erratic, all periodic wakeUpNotifications stop
        // and consequently BATTERYLEVEL IS NOT UPDATED ANYMORE every 24 hours, continuing to display the last (and obsolete) reported value.
        // Curiously, asynchronous sensorMultilevelReports continue to arrive, for some time, making the Device look (partially) "alive"
    	log.debug "wakeupv2.WakeUpNotification $cmd"
        def event = createEvent(descriptionText: "${device.displayName} woke up", isStateChange: true, displayed: false)
        def cmdBlock = []
        cmdBlock = wakeUpResponse([])
        return [event, response(cmdBlock)]
}

def zwaveEvent(hubitat.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd) {
	// IMPORTANT NOTE : when the batteryLevel becomes too low, Device reports become erratic, all periodic wakeUpNotifications stop
	// and consequently BATTERYLEVEL IS NOT UPDATED ANYMORE every 24 hours, continuing to display the last (and obsolete) reported value.
	// Curiously, asynchronous sensorMultilevelReports continue to arrive, for some time, making the Device look (partially) "alive"
	// This section resets the displayed battery level to 1% when the battery level is obsolete by more than 48h.
    state.batteryInterval = (long) (24*60-45)*60*1000  // 1 day
    def long nowTime = new Date().getTime()
    if (nowTime-state.lastReportBattery > 3*state.batteryInterval) {  // reset batteryLevel to 1% if no update for 48-72 hours
    	log.debug "obsolete (likely low) battery value : ${((nowTime-state.lastReportBattery)/3600000)} hours old"
        sendEvent(name: "battery", displayed: true, isStateChange:true, unit: "%", value: 1, descriptionText: "${device.displayName} has a low battery")
	    state.lastReportBattery = nowTime
	}
			//  Dirty temporary recovery fix for remote Devices which lost wakeUp capability but still get asynchromous SensorMultilevelReports
			//  Forcing with the magnet a close/open transition after replacing the battery should (in most cases...) restore wakeUps
                //def cmdBlock = []
        		//cmdBlock=wakeUpResponse(cmdBlock)
        		//return [response(cmdBlock)]
        		//configure()
        	log.debug "SensorMultilevelReport.precision : ${cmd.precision}"
            log.debug "SensorMultilevelReport.scale : ${cmd.scale}"
            log.debug "SensorMultilevelReport.scaledSensorValue : ${cmd.scaledSensorValue}"
            log.debug "SensorMultilevelReport.sensorType : ${cmd.sensorType}"
            log.debug "SensorMultilevelReport.sensorValue : ${cmd.sensorValue}"
            log.debug "SensorMultilevelReport.size : ${cmd.size}"
        def float scaledSensorValue = cmd.scaledSensorValue
        // Adjust measured temperature based on previous manual calibration; FGK-101 is natively °C
        switch (device.name) {
            case 'T005' :										//JJG	
            	scaledSensorValue = scaledSensorValue + 0.0554
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T006' :										//MLE
            	scaledSensorValue = scaledSensorValue + 0.0297
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T003' :										//MPT
            	scaledSensorValue = scaledSensorValue - 0.0603
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T002' :										//NBN	
            	scaledSensorValue = scaledSensorValue - 0.0758
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T004' :										//SCU
            	scaledSensorValue = scaledSensorValue + 0.0011
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T007' :										//FSU
            	scaledSensorValue = scaledSensorValue + 0.0025
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T008' :										
            	scaledSensorValue = scaledSensorValue - 0.0146
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T009' :										
            	scaledSensorValue = scaledSensorValue + 0.0383
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T010' :										
            	scaledSensorValue = scaledSensorValue + 0.0383
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T011' :										
            	scaledSensorValue = scaledSensorValue - 0.0889
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T012' :										
            	scaledSensorValue = scaledSensorValue - 0.0532
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T013' :										
            	scaledSensorValue = scaledSensorValue + 0.0383
    			log.debug "Temp Adjust for : ${device.name}"
                break;
            case 'T014' :										//*ext*//
            	scaledSensorValue = scaledSensorValue - 0.0160
    			log.debug "Temp Adjust for : ${device.name}"
                break;
        }
        //Round to nearest 1 decimal temperature value; convert to °F if needed
        def float ftempSign = temperatureScaleFC(scaledSensorValue) < 0 ? -1 : +1
		def float ftemp = ftempSign * ((((temperatureScaleFC(scaledSensorValue).abs()*100+5)/10).intValue()*1.0)/10)
        if (debugLevel>=2) {
        	log.debug "ftempSign : ${ftempSign}"
        	log.debug "ftemp : ${ftemp}"
        }
        nowTime = new Date().getTime()
        if (debugLevel>=2) {
        	log.debug "cmd.scaledSensorValue : ${cmd.scaledSensorValue}"
        	log.debug "correction : ${scaledSensorValue-cmd.scaledSensorValue}"
    		log.debug "device.displayName : ${device.displayName}"
    		log.debug "'Date().getTime()' : ${new Date().getTime()}"
            log.debug "state.maxEventInterval : ${state.maxEventInterval}"
    		log.debug "state.lastReportTime : ${state.lastReportTime}"
    		log.debug "nowTime : ${nowTime}"
            log.debug "device.forcedWakeUp : ${device.currentValue('forcedWakeUp')}"
    		log.debug "(nowTime-state.lastReportTime > state.maxEventInterval) : ${(nowTime-state.lastReportTime > state.maxEventInterval)}"
    		log.debug "ftemp : ${ftemp}"
            log.debug "state.lastReportedTemp: ${state.lastReportedTemp}"
        }
        // Adjust temperature report sensitivity for outside thermometers whose displayName starts with "*"
        def float tempQuantum
    	if (device.displayName.substring(0,1).equals("*")) {
        	tempQuantum = temperatureScaleFC(0.9999)-temperatureScaleFC(0)
        } else {
        	tempQuantum = temperatureScaleFC(0.2999)-temperatureScaleFC(0)
        }
        log.debug "device.forcedWakeUp : ${device.currentValue('forcedWakeUp')}"
        log.debug "((ftemp-state.lastReportedTemp).abs()>${tempQuantum}): ${(ftemp-state.lastReportedTemp).abs()>tempQuantum}"
        // Spurious faulty Temperature Reports cropped when temparture gradient is unbelievable (?)
        if ((((ftemp-state.lastReportedTemp).abs())/(nowTime-state.lastReportTime)) < (0.5/1000)) { // ignore temperature report when slope > 0.5°C/s
        if (((ftemp-state.lastReportedTemp).abs()>tempQuantum) || ((nowTime-state.lastReportTime) > state.maxEventInterval) || device.currentValue('forcedWakeUp')) {
        	def map = [ displayed: true, value: ftemp.toString(), isStateChange:true, linkText:"${device.displayName}" ]
        	if (cmd.sensorType == 1) {
                        map.name = "temperature"
                        map.unit = cmd.scale == 1 ? "F" : "C"
                        //ignores Device's native temperature scale, ftemp already converted to °F if settings as such
                        map.unit = location.temperatureScale
                        log.debug "map.value : ${map.value}"
                        log.debug "map.unit : ${map.unit}"
        	}
			if (debugLevel>=2) {
        		log.debug "temperature Command : ${map.inspect()}"
        	}
        	state.lastReportedTemp = ftemp
            state.lastReportTime = nowTime
            sendEvent(name: "forcedWakeUp", value: 0, displayed: false)
            // For Test purpose; redondant with reportNext() => device.forcedWakeUp=1
            if (device.currentValue('reportASAP')==1) {sendEvent(name: "reportASAP", value: 0, isStateChange: true)}
        	return createEvent(map)
        }
        } else {
        log.debug "+++++++++discarded temperature report : rate change : ${(((ftemp-state.lastReportedTemp).abs())/(nowTime-state.lastReportTime))*1000}°C/s"
        }
}

def sensorValueEvent(value) {
	if (value) {
		createEvent(name: "contact", value: "open", descriptionText: "$device.displayName is open  [sensorValueEvent]")
	} else {
		createEvent(name: "contact", value: "closed", descriptionText: "$device.displayName is closed  [sensorValueEvent]")
	}
}

// BasicReport should never occur since all status change notifications are asynchronous via BasicSet
def zwaveEvent(hubitat.zwave.commands.basicv1.BasicReport cmd) {
	sensorValueEvent(cmd.value)
    if (debugLevel>=2) {log.debug "basicv1.BasicReport $cmd.value"}
}

def openClosed(cmd, cmdValue) {
    def theState = cmdValue == 0 ? "closed" : "open"
    if (debugLevel>=2) {log.debug "openClosed $cmd"}
    // Use closed/open sensor notification to trigger push of updated Temperature value and immediate setting of updated device parameters
    // Sometimes, Temperature forced refresh stops working : SensorMultilevelGet(sensorType: 1, scale: 0) Commands are stacked but not executed immediately;
    // will restart after some time, and stacked Commands will be executed !
    def event = createEvent(name:"contact", value:"${theState}", descriptionText:"${device.displayName} is ${theState}", isStateChange:true, displayed:true, linkText:"${device.displayName}")
    sendEvent(name: "forcedWakeUp", value: 1, displayed: false)
    return [event, response(wakeUpResponse([]))]
}
    
// pre-ZW5 : BasicSet alarm does not seem to wait for any Commands answers, going back to sleep immediately;
//           thus it cannot perform proper initial Configuration => use the Tamper switch and SensorAlarmReport instead
def zwaveEvent(hubitat.zwave.commands.basicv1.BasicSet cmd) {
    log.debug "basicv1.BasicSet $cmd"
    if ((device.currentValue('ZW5set')) && (!(device.currentValue('ZW5')))) {
    	def cmdValue = cmd.value
		return openClosed(cmd, cmdValue)
    }
}

// For pre-ZW5, SensorBinaryReport should never occur since all status change notifications are asynchronous via BasicSet...
// ...but ZW5 uses it in addition to BasicSet and Notification
def zwaveEvent(hubitat.zwave.commands.sensorbinaryv2.SensorBinaryReport cmd) {
    log.debug "sensorbinaryv2.SensorBinaryReport $cmd"
    if ((device.currentValue('ZW5set')) && (!(device.currentValue('ZW5')))) {
    	def cmdValue = cmd.sensorValue
		return openClosed(cmd, cmdValue)
    }
}

// ZW5 : it is assumed that default notification events are used
// (parameter 20 was not changed before device's re-inclusion)
def zwaveEvent(hubitat.zwave.commands.notificationv3.NotificationReport cmd) {
    def map = [:]
    if (cmd.notificationType == 6) {
    	switch (cmd.event) {                
        	case 22:
            	map.name = "contact"
                map.value = "open"
                map.descriptionText = "${device.displayName} is open"
            	break
            case 23:
            	map.name = "contact"
                map.value = "closed"
                map.descriptionText = "${device.displayName} is closed"
            	break
        }
    // Contrary to pre-ZW5 Devices, the Tamper Notification does not occur for only a brief 
    // push>release of the Tamper button. But it DOES occur when the Tamper button is released
    // 1mn or so after being pushed.
    } else if (cmd.notificationType == 7) {
    	switch (cmd.event) {
        	case 0:
            	map.name = "tamper"
                map.value = "inactive"
                map.descriptionText = "${device.displayName} tamper detection enabled"
				break     
        	case 3:
            	map.name = "tamper"
                map.value = "active"
                map.descriptionText = "${device.displayName} is tampered with !"
            	break
        }
    }
    sendEvent(name: "forcedWakeUp", value: 1, displayed: false)
    def event = createEvent(map)
	return [event, response(wakeUpResponse([]))]
}

// SensorAlarmReport DOES wait for optional Commands answers, contrary to BasicSet
def zwaveEvent(hubitat.zwave.commands.sensoralarmv1.SensorAlarmReport cmd) {
    if (debugLevel>=2) {log.debug "sensoralarmv1.SensorAlarmReport $cmd.sensorState"}
    if (!(device.currentValue('ZW5'))) {
    	def event = createEvent(name:"alarm", descriptionText:"${device.displayName} is tampered with !", isStateChange:true, displayed:true, linkText:"${device.displayName}")
    	def cmdBlock = []
    	sendEvent(name: "forcedWakeUp", value: 1, displayed: false)
    	cmdBlock=wakeUpResponse(cmdBlock)
    	return [event, response(cmdBlock)]
    }
}

def zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd) {
    def long nowTime = new Date().getTime()
    if (debugLevel>=2) {
    	log.debug "batteryv1.BatteryReport ${cmd.batteryLevel}"
    	log.debug "nowTime : ${nowTime}"
    	log.debug "state.lastReportBattery : ${state.lastReportBattery}"
    	log.debug "state.batteryInterval : ${state.batteryInterval}"
        log.debug "device.forcedWakeUp : ${device.currentValue('forcedWakeUp')}"
    }
    if ((nowTime-state.lastReportBattery > state.batteryInterval) || device.currentValue('forcedWakeUp')) {
		def map = [ name: "battery", displayed: true, isStateChange:true, unit: "%" ]
		if (cmd.batteryLevel == 0xFF) {
			map.value = 1
			map.descriptionText = "${device.displayName} has a low battery"
			map.isStateChange = true
		} else {
			map.value = cmd.batteryLevel
		}
    	state.lastReportBattery = nowTime
        log.debug "battery map : ${map}"
        sendEvent(name: "forcedWakeUp", value: 0, displayed: false)
    	return [createEvent(map)]
    }
}

def zwaveEvent(hubitat.zwave.commands.configurationv2.ConfigurationReport cmd) {
    if (debugLevel>=2) {log.debug "ConfigurationReport - Parameter#${cmd.parameterNumber}: ${cmd.configurationValue}"}
	// Last configuration command execution; check UNIQUE(<>default) value is set
    // A bit of an overkill : checking the cmd.parameterNumber (12 or 51) should be enough...
	def byte tempQuantumSixteenth
	if (device.displayName.substring(0,1).equals("*")) {
		tempQuantumSixteenth = 16	/* 16/16=1°C = 1.8°F */
	} else {
		tempQuantumSixteenth = 5	/* 5/16=0.31°C = 0.56°F */
	}
	if (device.currentValue('ZW5set') && !(device.currentValue('ZW5')) && (cmd.parameterNumber == 12) && (cmd.configurationValue == [tempQuantumSixteenth])) {
		sendEvent(name: "Configured", value: 1, isStateChange: true)
		log.debug ("++++++Non-ZW5 Device Configured++++++")
	}
	def byte tempQuantumTenth
	if (device.displayName.substring(0,1).equals("*")) {
    	tempQuantumTenth = 10	/* 10/10=1°C = 1.8°F */
    } else {
    	tempQuantumTenth = 3	/* 3/10=0.3°C = 0.56°F */
    }
	if (device.currentValue('ZW5set') && device.currentValue('ZW5') && (cmd.parameterNumber == 51) && (cmd.configurationValue == [0,tempQuantumTenth])) {
		sendEvent(name: "Configured", value: 1, isStateChange: true)
		log.debug ("++++++ZW5 Device Configured++++++")
	}
}

def zwaveEvent(hubitat.zwave.commands.associationv2.AssociationReport cmd) {
	def result = []
	if (cmd.nodeId.any { it == zwaveHubNodeId }) {
		result << createEvent(descriptionText: "$device.displayName is associated in group ${cmd.groupingIdentifier}")
	} else if (cmd.groupingIdentifier == 1) {
		// We're not associated properly to group 1, set association
		result << createEvent(descriptionText: "Associating $device.displayName in group ${cmd.groupingIdentifier}")
		result << response(zwave.associationV1.associationSet(groupingIdentifier:cmd.groupingIdentifier, nodeId:zwaveHubNodeId))
	}
	result
}

def zwaveEvent(hubitat.zwave.commands.multichannelv3.MultiChannelEndPointReport cmd) {
    if (debugLevel>=2) {log.debug "multichannelv3.MultiChannelCapabilityReport: ${cmd}"}
}

def zwaveEvent(hubitat.zwave.commands.multichannelv3.MultiChannelCapabilityReport cmd) {
    if (debugLevel>=2) {log.debug "multichannelv3.MultiChannelCapabilityReport: ${cmd}"}
}

// ZW5 added : discriminate between ZW5 and pre-ZW5 Devices
// ZW5 : ${cmd.applicationVersion}.${cmd.applicationSubVersion}>=3.2 ; pre-ZW5 : <= 2.5
def zwaveEvent(hubitat.zwave.commands.versionv2.VersionReport cmd) {	
    //updateDataValue("version", "${cmd.applicationVersion}.${cmd.applicationSubVersion}")
    log.debug "versionv1.VersionReport: ${cmd}"
    log.debug "firmware0Version:        ${cmd.firmware0Version}"
    log.debug "firmware0SubVersion:     ${cmd.firmware0SubVersion}"
    def deviceFirmwareVersion = (java.lang.Short) cmd.firmware0Version*1000 + cmd.firmware0SubVersion
    log.debug "deviceFirmwareVersion: ${deviceFirmwareVersion}"
    if (deviceFirmwareVersion >= 3002) {
        sendEvent(name: "ZW5", value: 1, isStateChange: true)
    } else {
        sendEvent(name: "ZW5", value: 0, isStateChange: true)
    }
    sendEvent(name: "ZW5set", value: 1)
    log.debug "device.ZW5set: ${device.currentValue('ZW5set')}"
    log.debug "device.ZW5: ${device.currentValue('ZW5')}"
    return [response(wakeUpResponse([]))]
}
 
// MultiChannelCmdEncap and MultiInstanceCmdEncap are ways that devices can indicate that a message
// is coming from one of multiple subdevices or "endpoints" that would otherwise be indistinguishable
def zwaveEvent(hubitat.zwave.commands.multichannelv3.MultiChannelCmdEncap cmd) {
	def encapsulatedCommand = cmd.encapsulatedCommand([0x30: 2, 0x31: 5]) // can specify command class versions here like in zwave.parse
	if (debugLevel>=2) {log.debug ("Command from endpoint ${cmd.sourceEndPoint}: ${encapsulatedCommand}")}
	if (encapsulatedCommand) {
		return zwaveEvent(encapsulatedCommand)
	}
}

// Catch All command Handler in case of unexpected message
def zwaveEvent(hubitat.zwave.Command cmd) {
	createEvent(descriptionText: "!!! $device.displayName: ${cmd}", displayed: false)
}

// When a Temperature Event got lost in transit, the Watchdog requests a forced report at next wake up
// The "reportNext()" alarm command is used to signal back from the Watchdog SmartApp to the sleepy device
def reportNext(commandMsg) {
	log.debug "reportNext !"
    log.debug "commandMsg : ${commandMsg}"
    sendEvent(name: "forcedWakeUp", value: 1)
    	// IMPORTANT NOTE : when the batteryLevel becomes too low, Device reports become erratic, all periodic wakeUpNotifications stop
        // and consequently BATTERYLEVEL IS NOT UPDATED ANYMORE every 24 hours, continuing to display the last (and obsolete) reported value.
        // Curiously, asynchronous sensorMultilevelReports continue to arrive, for some time, making the Device look (partially) "alive"
    	// This section resets the displayed battery level to 1% when the battery level is obsolete by more than 48h.
	// Next line may be needed because "update()" does not seem to work reliably anymore
    state.batteryInterval = (long) (24*60-45)*60*1000  // 1 day
    def long nowTime = new Date().getTime()
    if (nowTime-state.lastReportBattery > 3*state.batteryInterval) {  // reset batteryLevel to 1% if no update for 48-72 hours
    	log.debug "obsolete (likely low) battery value : ${((nowTime-state.lastReportBattery)/3600000)} hours old"
        sendEvent(name: "battery", displayed: true, isStateChange:true, unit: "%", value: 1, descriptionText: "${device.displayName} has a low battery")
	    state.lastReportBattery = nowTime
	}
    return []
}

////////////////////////////////////////////////////
// Initial Device Configuration and Handler Update
////////////////////////////////////////////////////

// Executed each time the Handler is updated
def updated() {
	log.debug "Updated !"
    def bytesToCRC = [0x56, 0x01, 0x31, 0x05, 0x01, 0x42, 0x09, 0x79]
//log.debug "checksum 0BD3/3027 : zwaveCrc16([0x56, 0x01, 0x31, 0x05, 0x01, 0x42,0x09, 0x79]) : ${zwaveCrc16(bytesToCRC as byte[])}"
    sendEvent(name: "ZW5set", value: 0)
    sendEvent(name: "ZW5", value: 0)
    sendEvent(name: "Configured", value: 0)  // set to true by the LAST Command Response from configureDev()
    sendEvent(name: "forcedWakeUp", value: 1)
    // All state.xxx attributes are Device-local, NOT Location-wide
    // BEWARE : state.xxx attributes are vulnerable to race conditions; when not mostly read-only, use device.xxx instead
    state.lastReportedTemp = (float) -1000
    state.lastReportTime = (long) 0
    state.lastReportBattery = (long) 0
    state.longDelay = 1200
state.shortDelay = 1200
	// Real-time clock of sensors (ceramic resonator) is up to 3% inaccurate
    state.batteryInterval = (long) (24*60-45)*60*1000  // 83 700 000 : 1 Battery Report event every 24 hours, rounded up to the nearest hourly wakeup
    state.maxEventInterval = (long) (4*60-20)*60*1000  // 13 200 000 : at least 1 Temperature Report event every 3:40 hours (4 hours at most)
    state.parseCount=(int) 0
    if (!(state.deviceID)) {state.deviceID = device.name}
    log.debug "state.deviceID: ${state.deviceID}"
    log.debug "state.batteryInterval : ${state.batteryInterval}"
    log.debug "state.maxEventInterval : ${state.maxEventInterval}"
    // For Test purpose; redondant with reportNext() => device.forcedWakeUp=1
    sendEvent(name: "reportASAP", value: 1)
    log.debug "device.currentValue('reportASAP') : ${device.currentValue('reportASAP')}"
    // configureDev()		// will be defered till first wakeup (forced or periodic)
    infos()
}


// If you add the Configuration capability to your device type, this command will be called right
// after the device joins to set device-specific configuration commands.
def configure() {
    return configureDev()
    }
    
def configureDev() {
	def cmdBlock = []
    log.debug "device.ZW5set: ${device.currentValue('ZW5set')}"
    log.debug "device.ZW5: ${device.currentValue('ZW5')}"
    log.debug "device.Configured: ${device.currentValue('Configured')}"
    /////////////// Common configuration
    if (!(device.currentValue('ZW5set')))  {
    	log.debug "Configuring - Common Part............................................."
    	log.debug "cmdBlock: ${cmdBlock}"
		cmdBlock << zwave.versionV1.versionGet().format() 
        cmdBlock << "delay ${state.longDelay}"
        // batteryGet() should definitely NOT be CRC16 encoded ! [buggy ZW5 Fibaro handler !!]
		cmdBlock << zwave.batteryV1.batteryGet().format()
        cmdBlock << "delay ${state.longDelay}"
		cmdBlock << zwave.wakeUpV2.wakeUpNoMoreInformation().format()
    	log.debug "cmdBlock: ${cmdBlock}"
		log.debug "++++++Last Common Configuration Command SENT++++++"
		return cmdBlock
    }
    /////////////// Non-ZW5 specific configuration
    if (!(device.currentValue('Configured')) && device.currentValue('ZW5set') && !(device.currentValue('ZW5'))) {
		log.debug  "Configuring - NON ZW5............................................."
        // Make sure sleepy battery-powered sensors send their WakeUpNotifications to the hub
		cmdBlock << zwave.wakeUpV2.wakeUpIntervalSet(seconds:60*60, nodeid:zwaveHubNodeId).format()
        cmdBlock << "delay ${state.longDelay}"
        // Adjust temperature report sensitivity for outside thermometers whose displayName starts with "*"
		def byte tempQuantumSixteenth
		if (device.displayName.substring(0,1).equals("*")) {
			tempQuantumSixteenth = 16	/* 16/16=1°C = 1.8°F */
		} else {
			tempQuantumSixteenth = 5	/* 5/16=0.31°C = 0.56°F */
		}
		log.debug "tempQuantumSixteenth : ${tempQuantumSixteenth}"
		// NOTE : any asynchronous temperature query thru SensorMultilevelGet(sensorType: 1, scale: 0) does NOT reset the delta-Temp base value (managed by DS18B20 hardware)
		cmdBlock << zwave.configurationV2.configurationSet(parameterNumber: 12/*for FGK101*/, size: 1, configurationValue: [tempQuantumSixteenth]).format()
		cmdBlock << "delay ${state.longDelay}"
		// inclusion of Device in Association#3 is needed to get delta-Temperature notification messages [cf Parameter#12 above]
		cmdBlock << zwave.associationV2.associationSet(groupingIdentifier:3, nodeId:[zwaveHubNodeId]).format()
        cmdBlock << "delay ${state.longDelay}"
        // inclusion of Device in Association#2 is needed to enable SensorAlarmReport() Command [anti-Tampering protection]
        cmdBlock << zwave.associationV2.associationSet(groupingIdentifier:2, nodeId:[zwaveHubNodeId]).format()
        cmdBlock << "delay ${state.longDelay}"
        // DS18B20 temperature measurement at 12bits accuracy takes more than 750ms
		cmdBlock << zwave.multiChannelV3.multiChannelCmdEncap(sourceEndPoint: 2, destinationEndPoint: 2, commandClass:0x31, command:4).format()  //sensorMultiLevel.get()
		cmdBlock << "delay ${state.longDelay}"
        // Should be last for proper checking of complete initialization (through configurationReport)
		cmdBlock << zwave.configurationV2.configurationGet(parameterNumber: 12/*for FGK101*/).format()
		cmdBlock << "delay ${state.longDelay}"
		//cmdBlock << zwave.wakeUpV2.wakeUpNoMoreInformation().format()
        log.debug "++++++Last non-ZW5 Configuration Command SENT++++++"
    } 
    /////////////// ZW5 specific configuration
    if (!(device.currentValue('Configured')) && device.currentValue('ZW5set') && device.currentValue('ZW5')) {
    	log.debug "Configuring - ZW5............................................."
            //ZW5 : "wakeUpIntervalReport doesn’t work uint24FromBytes missing from response" : https://community.smartthings.com/t/wakeupintervalget-doesnt-work-uint24frombytes-missing-from-response/10577
            //cmdBlock << encap(zwave.wakeUpV2.wakeUpIntervalGet())
            //cmdBlock << "delay ${state.shortDelay}"
        // Make sure sleepy battery-powered sensors send their WakeUpNotifications to the hub
		cmdBlock << encap(zwave.wakeUpV2.wakeUpIntervalSet(seconds:60*60, nodeid:zwaveHubNodeId))
        cmdBlock << "delay ${state.shortDelay}"
        // Adjust temperature report sensitivity for outside thermometers whose displayName starts with "*"
    	def short tempQuantumTenth
    	log.debug "device.displayName.substring(0,1) : ${device.displayName.substring(0,1)}"
    	if (device.displayName.substring(0,1).equals("*")) {
    		tempQuantumTenth = 10	/* 10/10=1°C = 1.8°F */
    	} else {
    		tempQuantumTenth = 3	/* 3/10=0.3°C = 0.56°F */
    	}
    	// sensorMultilevelGet() should be +++PROPERLY+++ CRC16 encoded ! buggy ZW5 Fibaro handler w/ checksum = 0x0000 !!
        // ZW5 : completely buggy synchronous sensorMultilevelReport() : +/- 1°C vs unsolicited asynchronous reports : ???
        // DS18B20 temperature measurement at 12bits accuracy takes more than 750ms
cmdBlock << crc16Encode(zwave.sensorMultilevelV5.sensorMultilevelGet(sensorType: 1, scale: 0))
cmdBlock << "delay ${state.longDelay}"
        cmdBlock << encap(zwave.configurationV2.configurationSet(parameterNumber: 3/*for FGK101*/, size: 1, configurationValue: [5]))  // LED blinks on Tampering & Open/Close
        cmdBlock << "delay ${state.shortDelay}"
        // measuring temperature every 5mn drains the battery in a few months... but every hour creates a prejudiciable latency...
		cmdBlock << encap(zwave.configurationV2.configurationSet(parameterNumber: 50/*for FGK101*/, size: 2, configurationValue: [0x03,0x84]))  // measure temperature every 15mn = 900s = 0x384
		cmdBlock << "delay ${state.shortDelay}"
        cmdBlock << encap(zwave.configurationV2.configurationSet(parameterNumber: 51/*for FGK101*/, size: 2, configurationValue: [0,tempQuantumTenth]))  // less than 256...
        cmdBlock << "delay ${state.shortDelay}"
        // ??? : parameter#52 seems to translate "1 second" into "1.92 second", based on actual measurements
        //       => downrate 14 400 to 7 510 to compensate
        //cmdBlock << encap(zwave.configurationV2.configurationSet(parameterNumber: 52/*for FGK101*/, size: 2, configurationValue: [0x38,0x40]))  // 0x3840 = 14400 = 4*3600 = 4 hours
        cmdBlock << encap(zwave.configurationV2.configurationSet(parameterNumber: 52/*for FGK101*/, size: 2, configurationValue: [0x1D,0x56]))  // 0x1D56 = 7510
        cmdBlock << "delay ${state.shortDelay}"
        // 1st Association Group : "Lifeline" reports the device status and allows for assigning single device only (main controller by default)
        cmdBlock << encap(zwave.associationV2.associationSet(groupingIdentifier:1, nodeId: [zwaveHubNodeId]))
        cmdBlock << "delay ${state.shortDelay}"
        // 2nd Association Group : "Control" is assigned to the device status - reed sensor and IN input (sends alarm command frames).
        cmdBlock << encap(zwave.associationV2.associationSet(groupingIdentifier:2, nodeId: [zwaveHubNodeId]))
		cmdBlock << "delay ${state.shortDelay}"
        // Should be last for proper checking of complete initialization (through configurationReport)
		cmdBlock << encap(zwave.configurationV2.configurationGet(parameterNumber: 51/*for FGK101*/))
		cmdBlock << "delay ${state.shortDelay}"
		//cmdBlock << zwave.wakeUpV2.wakeUpNoMoreInformation().format()
    	log.debug "++++++Last ZW5 Configuration Command SENT++++++"
    }
    //log.debug "device.Configured: ${device.currentValue('Configured')}"
	return cmdBlock // Fully configured only after 2 Configure() calls
}  


def infos() {
	if (!state.devices) { state.devices = [:] }
    log.debug "zwaveHubNodeId: ${zwaveHubNodeId}"				// -> "1"
    log.debug "device.displayName: ${device.displayName}"		// -> "JJG"
    log.debug "device.id: ${device.id}"							// -> "d93f6450-4c9b-4892-bfcb-d61353f4c793"
    log.debug "location.id: ${location.id}"						// -> "99e95fb7-726f-4c64-a4f5-7b2151cf166a"  [Le Puits Jamet]
    log.debug "device.name: ${device.name}"						// -> "T005"
    log.debug "device.label: ${device.label}"					// -> "JJG"
    log.debug "device.data: ${device.data}"   					// -> "[MSR: 010F-0700-2000, endpointId: 0, version: 2.1]"
    log.debug "device.rawDescription: ${device.rawDescription}"	// -> non-ZW5 : "0 0 0x2001 0 0 0 c 0x30 0x9C 0x60 0x85 0x72 0x70 0x86 0x80 0x84 0x7A 0xEF 0x2B"
    // -> ZW5 : "zw:Ss type:0701 mfr:010F prod:0701 model:2001 cc:5E,59,22,80,56,7A,72,73,98,31,86 sec:85,20,70,5A,8E,71,2B,9C,30,84"
}

/**********************************************************************************************************
 *  Calculates the 16-bit CRC (CRC-CCITT) for a byte array.
 *  Uses initial crc of 0x1D0F, and poly of 0x1021, as per Z-wave specification.
 *  Reference: http://z-wave.sigmadesigns.com/wp-content/uploads/2016/08/SDS12652-13-Z-Wave-Command-Class-Specification-N-Z.pdf
 *  Thanks to CODERSAUR : https://community.smartthings.com/t/handling-crc-16-encapsulation-commands-crc16encap/76931/4
 **********************************************************************************************************/
 private zwaveCrc16(byte[] bytes) {
    short crc = 0x1D0F // It's important this is a short (16-bit)
    short poly = 0x1021
    bytes.each { workData ->
        //for (bitMask = 0x80; bitMask != 0; bitMask >>= 1) {
        // Need to use a different way to iterate, as rightshift operator '>>' and unsigned rightshift '>>>' do not appear to work in SmartThings.
        [0b10000000,0b01000000,0b00100000,0b00010000,0b00001000,0b00000100,0b00000010,0b00000001].each { bitMask ->
            def newBit = ((workData & bitMask) != 0) ^ ((crc & 0x8000) != 0);
            crc <<= 1;
            if (newBit) { crc ^= poly; }
         }
    }
    return crc
}

// CRC16 Encoding for Hub's +++OUTGOING+++ Commands
private crc16Encode(hubitat.zwave.Command cmd) {
	log.debug "cmd: ${cmd}"
	def bytesToCRC = [0x56, 0x01, cmd.commandClassId, cmd.commandId]
    bytesToCRC += cmd.payload
	log.debug "bytesToCRC: ${bytesToCRC}"
	def short checksum = zwaveCrc16(bytesToCRC as byte[])
	log.debug  "5601${cmd.format()}${Integer.toHexString(checksum & 0xFFFF).toUpperCase()}"
	return "5601${cmd.format()}${Integer.toHexString(checksum & 0xFFFF).toUpperCase()}"
}

//ZW5 added
private secure(hubitat.zwave.Command cmd) {
	zwave.securityV1.securityMessageEncapsulation().encapsulate(cmd).format()
}

//ZW5 added
private encap(hubitat.zwave.Command cmd) {
    def secureClasses = [0x20, 0x2B, 0x30, 0x5A, 0x70, 0x71, 0x84, 0x85, 0x8E, 0x9C]
    //todo: check if secure inclusion was successful
    //if not do not send security-encapsulated command
    if ((device.currentValue('ZW5set')) && (device.currentValue('ZW5'))) {
		if (secureClasses.find{ it == cmd.commandClassId }) {
    		secure(cmd)
    	} else {
        	// ??? : very dubious all UNsecure outgoing ZW5 commands have to be CRC16 encoded; 
            //		 sensorMultiLevelGet() MUST be, but for sure
            //       batteryGet() and versionGet() need NOT be ! (but could be ?)
    		crc16Encode(cmd)  // crc16() Fibaro code w/ checksum = 0x0000 was buggy
    	}
    } else {
    	return cmd.format()
    }
}

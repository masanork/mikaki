package app.mikaki.identity_proximity

import android.Manifest
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.app.Activity
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import app.tauri.annotation.*
import app.tauri.plugin.*
import java.io.ByteArrayOutputStream
import java.util.UUID

@InvokeArg
class ProximityArgs { var sessionId=""; var serviceUuid=""; var packet=""; var handoverSelect="";var nfcData=false; var negotiated=false; var expiresAt=0L }

/** ISO 18013-5 GATT peripheral. Fresh service UUID per Rust-owned session.
 * No addresses, packets, keys, identity data or permission results are logged.
 * UUIDs/framing checked against Multipaz; independent implementation, no reader code transplanted.
 */
@TauriPlugin
class IdentityProximityPlugin(private val activity:Activity):Plugin(activity) {
 private val main=Handler(Looper.getMainLooper())
 private val manager=activity.getSystemService(BluetoothManager::class.java)
 private val stateUuid=UUID.fromString("00000001-a123-48ce-896b-4c76973373e6")
 private val c2sUuid=UUID.fromString("00000002-a123-48ce-896b-4c76973373e6")
 private val s2cUuid=UUID.fromString("00000003-a123-48ce-896b-4c76973373e6")
 private val cccdUuid=UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
 private val tombstones=ArrayDeque<String>()
 private var foreground=true
 private class Session(val id:String,val uuid:UUID,var start:Invoke?) {
  val createdWall=System.currentTimeMillis();val createdElapsed=SystemClock.elapsedRealtime()
  var negotiated=false;var handoverPublished=false;var handoverRequest:ByteArray?=null;var receiveHandover:Invoke?=null;var handoverDelivered=false
  var nfcData=false;var handover:ByteArray?=null;var nfcPreferred=false; var permissionReady=false; var server:BluetoothGattServer?=null; var advertisement:AdvertiseCallback?=null
  var peer:BluetoothDevice?=null;var subscribed=false;var connected=false;var mtu=23
  var closed:Invoke?=null;var receive:Invoke?=null;var incoming=ByteArrayOutputStream();var ready:ByteArray?=null
  var requestDelivered=false;var send:Invoke?=null;var outgoing:ByteArray?=null;var offset=0
  var notifying=false;var deadline:Runnable?=null;var transferDeadline:TransferDeadline?=null
 }
 private var current:Session?=null
 private var pendingPermissionId:String?=null
 private val permissions=(activity as ComponentActivity).activityResultRegistry.register(
  "mikaki_identity_ble_permissions",ActivityResultContracts.RequestMultiplePermissions()) {
   main.post { val id=pendingPermissionId;pendingPermissionId=null;val s=current?.takeIf{it.id==id} ?:return@post; if (missing().isNotEmpty()) end(s,"ble_permission_denied") else {s.permissionReady=true;if(foreground)open(s)} }
 }
 private fun missing():List<String> = if(Build.VERSION.SDK_INT>=31) listOf(Manifest.permission.BLUETOOTH_ADVERTISE,Manifest.permission.BLUETOOTH_CONNECT).filter {ContextCompat.checkSelfPermission(activity,it)!=PackageManager.PERMISSION_GRANTED} else emptyList()
 @Command fun start(invoke:Invoke){
  val args=invoke.parseArgs(ProximityArgs::class.java)
  main.post {
   if(args.sessionId.length!=32||!args.sessionId.all{it in '0'..'9'||it in 'a'..'f'}||tombstones.contains(args.sessionId)||!foreground){invoke.reject("cancelled");return@post}
   if(current!=null||pendingPermissionId!=null){invoke.reject("ble_busy");return@post}
   val uuid=try{UUID.fromString(args.serviceUuid)}catch(_:Exception){invoke.reject("invalid_session");return@post}
   val s=Session(args.sessionId,uuid,invoke);s.negotiated=args.negotiated;current=s
   if(args.nfcData) {
    s.nfcData=true
    try {
     require(args.handoverSelect.isEmpty())
     require(activity.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION))
     val adapter=NfcAdapter.getDefaultAdapter(activity);require(adapter!=null&&adapter.isEnabled)
     require(CardEmulation.getInstance(adapter).setPreferredService(activity,ComponentName(activity,IdentityEngagementService::class.java)))
     s.nfcPreferred=true
     if(s.negotiated) armNegotiation(s) else armData(s,false)
     s.deadline=Runnable{end(s,"nfc_timeout")};main.postDelayed(s.deadline!!,120000)
     s.start?.resolve();s.start=null
    }catch(_:Exception){end(s,"nfc_unavailable")}
    return@post
   }
   if(args.handoverSelect.isNotEmpty()||s.negotiated) {
    try {
     require(args.handoverSelect.length<=5460)
     require(activity.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION))
     val adapter=NfcAdapter.getDefaultAdapter(activity);require(adapter!=null&&adapter.isEnabled)
     val message=Base64.decode(args.handoverSelect,Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
     require((s.negotiated&&message.isEmpty())||(!s.negotiated&&message.isNotEmpty()&&message.size<=4094))
     s.handover=message
    } catch(_:Exception){end(s,"nfc_unavailable");return@post}
   }
   s.deadline=Runnable{end(s,"ble_timeout")};main.postDelayed(s.deadline!!,120000)
   try {val absent=missing();if(absent.isEmpty()){s.permissionReady=true;open(s)}else {pendingPermissionId=s.id;permissions.launch(absent.toTypedArray())}}catch(_:Exception){if(pendingPermissionId==s.id)pendingPermissionId=null;end(s,"ble_start_failed")}
  }
 }
 private fun armNegotiation(s:Session) {
  EngagementState.armNegotiated(s.id,{request->main.post{if(current===s&&!s.handoverDelivered&&s.handoverRequest==null){s.handoverRequest=request;deliverHandover(s)}else request.fill(0)}},{main.post{if(current===s)end(s,"nfc_handover_failed")}})
 }
 private fun armData(s:Session,afterHandover:Boolean) {
  NfcDataState.arm(s.id,{packet->if(current===s&&!s.requestDelivered){s.ready=packet;deliver(s)}else packet.fill(0)},
   {main.post{if(current===s){s.send?.resolve();s.send=null}}},
   {main.post{if(current===s)end(s,"nfc_disconnected")}},afterHandover)
 }
 private fun open(s:Session){
  if(current!==s||s.server!=null)return
  try {
   val adapter=manager.adapter
   require(adapter!=null&&adapter.isEnabled&&adapter.isMultipleAdvertisementSupported)
   s.server=manager.openGattServer(activity,callback(s)) ?:error("server")
   val service=BluetoothGattService(s.uuid,BluetoothGattService.SERVICE_TYPE_PRIMARY)
   val state=BluetoothGattCharacteristic(stateUuid,BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,BluetoothGattCharacteristic.PERMISSION_WRITE)
   val client=BluetoothGattCharacteristic(c2sUuid,BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or BluetoothGattCharacteristic.PROPERTY_WRITE,BluetoothGattCharacteristic.PERMISSION_WRITE)
   val server=BluetoothGattCharacteristic(s2cUuid,BluetoothGattCharacteristic.PROPERTY_NOTIFY,0)
   for(c in listOf(state,server))c.addDescriptor(BluetoothGattDescriptor(cccdUuid,BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE))
   service.addCharacteristic(state);service.addCharacteristic(client);service.addCharacteristic(server)
   require(s.server!!.addService(service))
  }catch(_:Exception){end(s,"ble_unavailable")}
 }
 private fun callback(s:Session)=object:BluetoothGattServerCallback(){
  override fun onServiceAdded(status:Int,service:BluetoothGattService){main.post{
   if(current!==s)return@post
   if(status!=BluetoothGatt.GATT_SUCCESS){end(s,"ble_start_failed");return@post}
   try {
    val callback=object:AdvertiseCallback(){override fun onStartSuccess(settings:AdvertiseSettings){main.post{if(current===s){try {
      s.handover?.let { message ->
       val emulation=CardEmulation.getInstance(NfcAdapter.getDefaultAdapter(activity))
       require(emulation.setPreferredService(activity,ComponentName(activity,IdentityEngagementService::class.java)))
       s.nfcPreferred=true
       if(s.negotiated) armNegotiation(s)
       else EngagementState.arm(s.id,message)
      }
      s.start?.resolve();s.start=null
     }catch(_:Exception){end(s,"nfc_unavailable")}}}};override fun onStartFailure(code:Int){main.post{end(s,"ble_start_failed")}}}
    s.advertisement=callback
    manager.adapter.bluetoothLeAdvertiser!!.startAdvertising(AdvertiseSettings.Builder().setConnectable(true).setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setTimeout(0).build(),AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(ParcelUuid(s.uuid)).build(),callback)
   }catch(_:Exception){end(s,"ble_start_failed")}
  }}
  override fun onConnectionStateChange(device:BluetoothDevice,status:Int,newState:Int){main.post{
   if(current!==s)return@post
   if(status!=BluetoothGatt.GATT_SUCCESS){end(s,"ble_connection_failed");return@post}
   if(newState==BluetoothProfile.STATE_CONNECTED){if(s.peer!=null&&s.peer!=device){try{s.server?.cancelConnection(device)}catch(_:Exception){};return@post};s.peer=device}
   else if(newState==BluetoothProfile.STATE_DISCONNECTED&&s.peer==device)end(s,"ble_disconnected")
  }}
  override fun onMtuChanged(device:BluetoothDevice,mtu:Int){main.post{if(current===s&&s.peer==device)s.mtu=mtu.coerceIn(23,517)}}
  override fun onDescriptorWriteRequest(device:BluetoothDevice,requestId:Int,descriptor:BluetoothGattDescriptor,preparedWrite:Boolean,responseNeeded:Boolean,offset:Int,value:ByteArray){main.post{
   if(current!==s)return@post
   val valid=s.peer==device&&!preparedWrite&&offset==0&&descriptor.uuid==cccdUuid&&(descriptor.characteristic.uuid==s2cUuid||descriptor.characteristic.uuid==stateUuid)&&value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
   if(valid&&descriptor.characteristic.uuid==s2cUuid)s.subscribed=true
   if(responseNeeded)try{s.server?.sendResponse(device,requestId,if(valid)BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,0,null)}catch(_:Exception){end(s,"ble_error")}
   if(!valid)end(s,"invalid_ble_subscription")
  }}
  override fun onDescriptorReadRequest(device:BluetoothDevice,requestId:Int,offset:Int,descriptor:BluetoothGattDescriptor){main.post{
   if(current!==s)return@post
   try{s.server?.sendResponse(device,requestId,if(s.peer==device&&offset==0)BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,0,if(s.subscribed)BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE else BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)}catch(_:Exception){end(s,"ble_error")}
  }}
  override fun onCharacteristicWriteRequest(device:BluetoothDevice,requestId:Int,characteristic:BluetoothGattCharacteristic,preparedWrite:Boolean,responseNeeded:Boolean,offset:Int,value:ByteArray){main.post{
   if(current!==s)return@post
   var valid=s.peer==device&&!preparedWrite&&offset==0
   if(valid) when(characteristic.uuid){
    stateUuid -> {valid=value.size==1; if(valid)when(value[0].toInt()){1->{valid=s.subscribed&&!s.connected&&(!s.negotiated||s.handoverPublished);if(valid){s.connected=true;clearEngagement(s);try{s.advertisement?.let{manager.adapter.bluetoothLeAdvertiser?.stopAdvertising(it)}}catch(_:Exception){}}};2->{if(responseNeeded)try{s.server?.sendResponse(device,requestId,BluetoothGatt.GATT_SUCCESS,0,null)}catch(_:Exception){};end(s,"ble_peer_terminated");return@post};else->valid=false}}
    c2sUuid -> {valid=s.connected&&!s.requestDelivered&&s.ready==null&&value.size in 2..(s.mtu-3)&&value[0].toInt() in 0..1&&s.incoming.size()+value.size-1<=32000
     if(valid){s.incoming.write(value,1,value.size-1);if(value[0].toInt()==0){s.ready=s.incoming.toByteArray();s.incoming.reset();deliver(s)}}}
    else -> valid=false
   }
   if(responseNeeded)try{s.server?.sendResponse(device,requestId,if(valid)BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,0,null)}catch(_:Exception){end(s,"ble_error")}
   if(!valid)end(s,"invalid_ble_packet")
  }}
  override fun onNotificationSent(device:BluetoothDevice,status:Int){main.post{
   if(current!==s||s.peer!=device||!s.notifying)return@post
   if(!transferLive(s))return@post
   s.notifying=false
   if(status!=BluetoothGatt.GATT_SUCCESS){end(s,"ble_send_failed");return@post}
   val data=s.outgoing?:return@post
   if(s.offset==data.size){data.fill(0);s.outgoing=null;s.send?.resolve();s.send=null}else next(s)
  }}
 }
 private fun deliverHandover(s:Session){val invoke=s.receiveHandover?:return;val data=s.handoverRequest?:return;s.receiveHandover=null;s.handoverRequest=null;s.handoverDelivered=true;invoke.resolve(JSObject().apply{put("packet",Base64.encodeToString(data,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))});data.fill(0)}
 @Command fun receiveHandover(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{val s=current;if(s==null||s.id!=args.sessionId||!s.negotiated||s.handoverDelivered||s.receiveHandover!=null){invoke.reject("handover_unavailable");return@post};s.receiveHandover=invoke;deliverHandover(s)}}
 @Command fun publishHandover(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{val s=current;if(s==null||s.id!=args.sessionId||!s.negotiated||!s.handoverDelivered||s.handoverPublished){invoke.reject("handover_unavailable");return@post};try{require(args.packet.length<=5460);val message=Base64.decode(args.packet,Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP);EngagementState.publish(s.id,message);if(s.nfcData)armData(s,true);s.handoverPublished=true;invoke.resolve()}catch(_:Exception){invoke.reject("invalid_handover");end(s,"nfc_handover_failed")}}}
 private fun deliver(s:Session){val invoke=s.receive?:return;val data=s.ready?:return;s.ready=null;s.receive=null;s.requestDelivered=true;invoke.resolve(JSObject().apply{put("packet",Base64.encodeToString(data,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))});data.fill(0)}
 @Command fun waitClosed(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{val s=current;if(s==null||s.id!=args.sessionId){invoke.resolve();return@post};if(s.closed!=null){invoke.reject("watcher_exists");return@post};s.closed=invoke}}
 @Command fun receive(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{val s=current;if(s==null||s.id!=args.sessionId||s.receive!=null||s.requestDelivered){invoke.reject("ble_session_unavailable");return@post};s.receive=invoke;deliver(s)}}
 @Command fun send(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{
  val s=current;if(s==null||s.id!=args.sessionId||(!s.nfcData&&(!s.connected||!s.subscribed))||!s.requestDelivered||s.send!=null||s.transferDeadline!=null){invoke.reject("ble_session_unavailable");return@post}
  try{
   val expiry=TransferDeadline.fromEpochSeconds(args.expiresAt,s.createdWall,s.createdElapsed)
   s.transferDeadline=expiry
   s.deadline?.let{main.removeCallbacks(it)}
   s.deadline=Runnable{end(s,"presentation_expired")}
   main.postDelayed(s.deadline!!,expiry.remainingMillis(System.currentTimeMillis(),SystemClock.elapsedRealtime()))
   if(s.nfcData)NfcDataState.limitTransfer(s.id,expiry)
   if(!transferLive(s)){invoke.reject("presentation_expired");return@post}
   require(args.packet.length<=43000);val data=Base64.decode(args.packet,Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP);require(data.isNotEmpty()&&data.size<=32000);s.send=invoke;if(s.nfcData){try{NfcDataState.send(s.id,data)}finally{data.fill(0)}}else{s.outgoing=data;s.offset=0;next(s)}}catch(_:Exception){invoke.reject("invalid_ble_packet");end(s,"ble_send_failed")}
 }}
 private fun transferLive(s:Session):Boolean {
  if(current!==s)return false
  val expiry=s.transferDeadline
  if(expiry==null||expiry.expired(System.currentTimeMillis(),SystemClock.elapsedRealtime())){end(s,"presentation_expired");return false}
  return true
 }
 @Suppress("DEPRECATION") private fun next(s:Session){
  if(!transferLive(s))return
  try{val data=s.outgoing?:return;val peer=s.peer?:error("peer");val characteristic=s.server!!.getService(s.uuid).getCharacteristic(s2cUuid);val n=minOf(s.mtu-4,data.size-s.offset);val chunk=ByteArray(n+1);chunk[0]=(if(s.offset+n<data.size)1 else 0).toByte();data.copyInto(chunk,1,s.offset,s.offset+n);s.offset+=n;s.notifying=true
   val sent=if(Build.VERSION.SDK_INT>=33)s.server!!.notifyCharacteristicChanged(peer,characteristic,false,chunk)==BluetoothStatusCodes.SUCCESS else {characteristic.value=chunk;s.server!!.notifyCharacteristicChanged(peer,characteristic,false)}
   if(!sent)end(s,"ble_send_failed")
  }catch(_:Exception){end(s,"ble_send_failed")}
 }
 @Command fun close(invoke:Invoke){val args=invoke.parseArgs(ProximityArgs::class.java);main.post{if(!tombstones.contains(args.sessionId)){tombstones.addLast(args.sessionId);if(tombstones.size>16)tombstones.removeFirst()};current?.takeIf{it.id==args.sessionId}?.let{end(it,"cancelled")};invoke.resolve()}}
 private fun clearEngagement(s:Session){
  NfcDataState.clear(s.id);EngagementState.clear(s.id);s.handover?.fill(0);s.handover=null
  if(s.nfcPreferred){s.nfcPreferred=false;try{CardEmulation.getInstance(NfcAdapter.getDefaultAdapter(activity)).unsetPreferredService(activity)}catch(_:Exception){}}
 }
 private fun end(s:Session,error:String){
  if(current!==s)return;current=null;clearEngagement(s);s.deadline?.let{main.removeCallbacks(it)}
  s.receiveHandover?.reject(error);s.receiveHandover=null;s.handoverRequest?.fill(0);s.handoverRequest=null
  s.start?.reject(error);s.receive?.reject(error);s.send?.reject(error);s.closed?.resolve();s.closed=null;s.start=null;s.receive=null;s.send=null
  s.ready?.fill(0);s.outgoing?.fill(0);s.incoming.reset()
  try{s.advertisement?.let{manager.adapter.bluetoothLeAdvertiser?.stopAdvertising(it)}}catch(_:Exception){}
  try{s.server?.close()}catch(_:Exception){};s.server=null
 }
 override fun onPause(activity:AppCompatActivity){foreground=false;main.post{current?.let{if(pendingPermissionId!=it.id)end(it,"cancelled")}}}
 override fun onResume(activity:AppCompatActivity){foreground=true;main.post{current?.let{if(!it.nfcData&&it.permissionReady&&it.server==null)open(it)}}}
 override fun onDestroy(activity:AppCompatActivity){foreground=false;main.post{current?.let{end(it,"cancelled")}};permissions.unregister()}
}

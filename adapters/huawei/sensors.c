#include "../../core/sensor_compat_internal.h"
#include <string.h>
static yyjson_mut_val *field(yyjson_mut_val *object,const char *key){return yyjson_mut_is_obj(object)?yyjson_mut_obj_get(object,key):NULL;}
static yyjson_mut_val *vendor(yyjson_mut_val *object){return field(field(object,"Oem"),"Huawei");}
static void copy_number(yyjson_mut_doc *doc,yyjson_mut_val *object,const char *key,yyjson_mut_val *value){
    if(yyjson_mut_is_num(value)&&!yyjson_mut_is_num(field(object,key)))yyjson_mut_obj_put(object,yyjson_mut_str(doc,key),yyjson_mut_val_mut_copy(doc,value));
}
static void supply(yyjson_mut_doc *doc,yyjson_mut_val *item){
    yyjson_mut_val *oem=vendor(item),*watts=field(oem,"PowerOutputWatts");
    if(!yyjson_mut_is_num(watts))watts=field(oem,"PowerInputWatts");
    copy_number(doc,item,"PowerOutputWatts",watts);copy_number(doc,item,"OutputVoltage",field(oem,"OutputVoltage"));
}
static void sensor(yyjson_mut_doc *doc,yyjson_mut_val *item){
    if(!yyjson_mut_is_obj(item))return;
    yyjson_mut_val *value=field(item,"ReadingValue");
    if(value)yyjson_mut_obj_put(item,yyjson_mut_str(doc,"Reading"),yyjson_mut_val_mut_copy(doc,value));
    value=field(item,"SensorId");if(value)yyjson_mut_obj_put(item,yyjson_mut_str(doc,"SensorNumber"),yyjson_mut_val_mut_copy(doc,value));
    const char *unit=yyjson_mut_get_str(field(item,"Unit")),*canonical=unit?unit:"",*type="Discrete";
    if(unit){if(!strcmp(unit,"degrees C")||!strcmp(unit,"Celsius")){canonical="Cel";type="Temperature";}
        else if(!strcmp(unit,"Volts")){canonical="V";type="Voltage";}
        else if(!strcmp(unit,"Watts")){canonical="W";type="Power";}
        else if(!strcmp(unit,"Amps")){canonical="A";type="Current";}
        else if(!strcmp(unit,"RPM")){canonical="RPM";type="Rotational";}}
    yyjson_mut_obj_put(item,yyjson_mut_str(doc,"ReadingUnits"),yyjson_mut_strcpy(doc,canonical));
    yyjson_mut_obj_put(item,yyjson_mut_str(doc,"ReadingType"),yyjson_mut_strcpy(doc,type));
    const char *status=yyjson_mut_get_str(field(item,"Status"));
    if(status){const char *health=status,*state=status;
        if(!strcmp(status,"ok")||!strcmp(status,"Normal")||!strcmp(status,"OK")){health="OK";state="Enabled";}
        else if(!strcmp(status,"nc")){health="Warning";state="Enabled";}
        else if(!strcmp(status,"cr")||!strcmp(status,"UpperCritical")||!strcmp(status,"LowerCritical")){health="Critical";state="Enabled";}
        yyjson_mut_val *object=yyjson_mut_obj(doc);yyjson_mut_obj_add_strcpy(doc,object,"Health",health);yyjson_mut_obj_add_strcpy(doc,object,"State",state);
        yyjson_mut_obj_put(item,yyjson_mut_str(doc,"Status"),object);
    }
}
bc_status bc_huawei_sensor_normalize(yyjson_mut_doc *doc,yyjson_mut_val *root,char links[2][1025]){
    yyjson_mut_val *oem=vendor(root);const char *names[]={"ThresholdSensors","DiscreteSensors"};
    for(uint32_t i=0;i<2;++i){const char *uri=yyjson_mut_get_str(field(field(oem,names[i]),"@odata.id"));
        if(uri){size_t n=strlen(uri);if(!n||n>1024)return BC_PROTOCOL_ERROR;memcpy(links[i],uri,n+1);}}
    yyjson_mut_val *array=field(root,"Sensors");
    if(array&&!yyjson_mut_is_arr(array))return BC_PROTOCOL_ERROR;
    if(yyjson_mut_arr_size(array)>4096)return BC_LIMIT_EXCEEDED;
    size_t index,max;yyjson_mut_val *item;
    yyjson_mut_arr_foreach(array,index,max,item){sensor(doc,item);}
    supply(doc,root);array=field(root,"PowerSupplies");
    yyjson_mut_arr_foreach(array,index,max,item){supply(doc,item);}
    return BC_OK;
}

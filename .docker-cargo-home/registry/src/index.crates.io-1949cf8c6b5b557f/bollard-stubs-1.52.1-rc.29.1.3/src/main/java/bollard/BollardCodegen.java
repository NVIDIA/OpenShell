package bollard;

import com.google.common.base.CaseFormat;
import io.swagger.codegen.*;
import io.swagger.codegen.languages.RustServerCodegen;
import io.swagger.models.properties.*;

import io.swagger.models.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.Map.Entry;

public class BollardCodegen extends RustServerCodegen {
    private static final Logger LOGGER = LoggerFactory.getLogger(BollardCodegen.class);

    public BollardCodegen() {
        super();
        typeMapping.put("DateTime", "BollardDate");
        supportingFiles.add(
                new SupportingFile("query_parameters.mustache", "src", "query_parameters.rs")
        );
        CliOption option = new CliOption("queryParameterMappings",
                "Mapping Swagger to legacy Bollard Query Parameter types, delimited by comma and colon");

        cliOptions.add(option);

        supportsInheritance = false;
        supportsMixins = true;
    }

    // Declare custom additions to inline enums that are behaving differently
    // than the official spec
    private static HashMap<String, List<Map<String, String>>> patchEnumValues;
    static {
        patchEnumValues = new HashMap<String, List<Map<String, String>>>();
        Map<String, String> additionalEnumValues = new HashMap<String, String>();
        List<Map<String, String>> enumValues = new ArrayList<Map<String, String>>();

        additionalEnumValues.put("name", "ROLLBACK_STARTED");
        additionalEnumValues.put("value", "\"rollback_started\"");
        enumValues.add(additionalEnumValues);

        additionalEnumValues = new HashMap<String, String>();
        additionalEnumValues.put("name", "ROLLBACK_PAUSED");
        additionalEnumValues.put("value", "\"rollback_paused\"");
        enumValues.add(additionalEnumValues);

        additionalEnumValues = new HashMap<String, String>();
        additionalEnumValues.put("name", "ROLLBACK_COMPLETED");
        additionalEnumValues.put("value", "\"rollback_completed\"");
        enumValues.add(additionalEnumValues);

        patchEnumValues.put("ServiceUpdateStatusStateEnum", enumValues);
    }

    private static ArrayList<String> enumToString;
    static {
        enumToString = new ArrayList();
        enumToString.add("HostConfigLogConfig");
    }

    private static ArrayList<String> upperCaseModelFields;
    static {
        upperCaseModelFields = new ArrayList();
        upperCaseModelFields.add("IdResponse");
    }

    private HashMap<String, String> queryParameterMappings = new HashMap();

    @Override
    public void preprocessSwagger(Swagger swagger) {
        Info info = swagger.getInfo();
        List versionComponents = new ArrayList();
        versionComponents.add((String) additionalProperties.get(CodegenConstants.PACKAGE_VERSION));

        info.setVersion(StringUtils.join(versionComponents, "."));

        String cliOptionQueryParameterMappings = (String) additionalProperties.get("queryParameterMappings");
        if (cliOptionQueryParameterMappings != null) {
            for (String cliOptionline : cliOptionQueryParameterMappings.split("\n")) {
                String[] cliOptionLineSplit = cliOptionline.split("=");
                if (cliOptionLineSplit.length == 2) {
                    queryParameterMappings.put(cliOptionLineSplit[0].trim(), cliOptionLineSplit[1].trim());
                }
            }
        }

        super.preprocessSwagger(swagger);
    }

    @Override
    public String getTypeDeclaration(Property p) {
        String type = super.getTypeDeclaration(p);

        // This is a "fallback" type, and allows some parts of the Docker API
        // that receive an empty JSON '{}' value.
        if ("object".equals(type) && "object".equals(p.getType())) {
            type = "HashMap<(), ()>";
        }

        return type;
    }

    @Override
    public CodegenProperty fromProperty(String name, Property p) {
        CodegenProperty property = super.fromProperty(name, p);

        // Remove extraneous references
        if (property.datatype.startsWith("models::")) {
            property.datatype = property.datatype.replace("models::", "");
        }

        return property;
    }

    @Override
    public Map<String, Object> postProcessAllModels(Map<String, Object> objs) {
        Map<String, Object> newObjs = super.postProcessAllModels(objs);

        // Index all CodegenModels by model name.
        HashMap<String, CodegenModel> allModels = new HashMap<String, CodegenModel>();
        for (Entry<String, Object> entry : objs.entrySet()) {
            String modelName = toModelName(entry.getKey());
            Map<String, Object> inner = (Map<String, Object>) entry.getValue();
            List<Map<String, Object>> models = (List<Map<String, Object>>) inner.get("models");
            for (Map<String, Object> mo : models) {
                CodegenModel cm = (CodegenModel) mo.get("model");
                allModels.put(modelName, cm);
            }
        }

        for (Entry<String, CodegenModel> entry : allModels.entrySet()) {
            CodegenModel model = entry.getValue();

            // Handle Container Update body
            if ("Resources".equals(model.classname)) {
                CodegenModel containerUpdateBody = new CodegenModel();
                containerUpdateBody.name = "ContainerUpdateBody";
                containerUpdateBody.classname = "ContainerUpdateBody";
                containerUpdateBody.vars = new ArrayList<>(model.vars);

                CodegenProperty restartPolicyProp = new CodegenProperty();
                restartPolicyProp.name = "restart_policy";
                restartPolicyProp.baseName = "RestartPolicy";
                restartPolicyProp.datatype = "RestartPolicy";
                restartPolicyProp.required = false;
                containerUpdateBody.vars.add(restartPolicyProp);

                Map<String, Object> inner = new HashMap<String, Object>();
                List<Map<String, Object>> models = new ArrayList<>();
                Map<String, Object> inside = new HashMap<String, Object>();
                inside.put("model", containerUpdateBody);
                models.add(inside);
                inner.put("models", models);
                newObjs.put("ContainerUpdateBody", inner);
            }

            // Handle Container Create body
            if ("ContainerConfig".equals(model.classname)) {
                CodegenModel containerCreateBody = new CodegenModel();
                containerCreateBody.name = "ContainerCreateBody";
                containerCreateBody.classname = "ContainerCreateBody";
                containerCreateBody.vars = new ArrayList<>(model.vars);
                CodegenModel hostConfig = allModels.get("HostConfig");

                CodegenProperty hostConfigProp = new CodegenProperty();
                hostConfigProp.name = "host_config";
                hostConfigProp.baseName = "HostConfig";
                hostConfigProp.datatype = "HostConfig";
                hostConfigProp.required = false;
                containerCreateBody.vars.add(hostConfigProp);

                CodegenProperty networkingConfigProp = new CodegenProperty();
                networkingConfigProp.name = "networking_config";
                networkingConfigProp.baseName = "NetworkingConfig";
                networkingConfigProp.datatype = "NetworkingConfig";
                networkingConfigProp.required = false;
                containerCreateBody.vars.add(networkingConfigProp);

                Map<String, Object> inner = new HashMap<String, Object>();
                List<Map<String, Object>> models = new ArrayList<>();
                Map<String, Object> inside = new HashMap<String, Object>();
                inside.put("model", containerCreateBody);
                models.add(inside);
                inner.put("models", models);
                newObjs.put("ContainerCreateBody", inner);
            }


            // Special case for numeric Enums
            if (model.isEnum && model.dataType != null && (model.dataType.equals("i8") || model.dataType.equals("i16") || model.dataType.equals("i32") || model.dataType.equals("i64"))) {
                model.vendorExtensions.put("x-rustgen-numeric-enum", true);
                ArrayList<HashMap<String, String>> lst = (ArrayList) model.allowableValues.get("enumVars");
                for (HashMap<String, String> enumVar : lst) {
                    String val = enumVar.get("value");
                    enumVar.put("value", val.replace("\"", ""));
                }
            }

            for (CodegenProperty prop : model.vars) {
                if (prop.name.contains("i_pv6")) {
                    prop.name = prop.name.replace("i_pv6", "ipv6");
                } else if (prop.name.contains("i_pv4")) {
                    prop.name = prop.name.replace("i_pv4", "ipv4");
                } else if (prop.name.contains("_i_ops")) {
                    prop.name = prop.name.replace("_i_ops", "_iops");
                } else if (prop.name.contains("_i_ds")) {
                    prop.name = prop.name.replace("_i_ds", "_ids");
                } else if (prop.name.contains("_c_as")) {
                    prop.name = prop.name.replace("_c_as", "_cas");
                } else if (prop.name.equals("_type")) {
                    prop.name = "typ";
                }

                if (prop.name.equals("aux") && model.classname.equals("BuildInfo")) {
                    prop.vendorExtensions.put("x-rustgen-grpc-aux", true);
                    model.vendorExtensions.put("x-rustgen-grpc-aux", true);
                }

                if (prop.name.equals("networks") && model.classname.equals("ContainerStatsResponse")) {
                    prop.datatype = "HashMap<String, ContainerNetworkStats>";
                }

                if ("SystemVersionComponents".equals(model.classname) && "details".equals(prop.name)) {
                    prop.datatype = "HashMap<String, String>";
                }

                if (upperCaseModelFields.contains(model.classname)) {
                    ArrayList<String> aliases = new ArrayList<String>();
                    aliases.add(CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.UPPER_CAMEL, prop.baseName));
                    aliases.add(prop.baseName.toUpperCase());
                    prop.vendorExtensions.put("x-rustgen-upper-case", aliases);
                }

                if (prop.dataFormat != null && (prop.dataFormat.equals("dateTime") || prop.datatype.equals("BollardDate"))) {
                    // set DateTime format on properties where appropriate
                    prop.vendorExtensions.put("x-rustgen-is-datetime", true);
                    prop.datatype = "BollardDate";
                }

                // Catch the moby-specific json-compatible encoding: {"<port>/<tcp|udp|sctp>": {}}`
                if (prop.datatype.equals("HashMap<String, HashMap<(), ()>>")) {
                    prop.vendorExtensions.put("x-rustgen-is-hashmap-string-hashmap-empty", "true");
                    prop.datatype = "Vec<String>";
                    prop.datatypeWithEnum = "Vec<String>";
                    prop.isMapContainer = false;
                    prop.isListContainer = true;
                    prop.items.datatype = "String";
                }

                if (prop.isEnum) {
                    if (enumToString.contains(model.classname)) {
                        prop.isEnum = false;
                    }
                    ArrayList<HashMap<String, String>> vars = (ArrayList<HashMap<String, String>>) prop.allowableValues
                            .get("enumVars");
                    for (HashMap<String, String> enumVar : vars) {
                        String enumValue = enumVar.get("value");

                        // ensure we can deserialize inline enum values encoded as empty strings
                        if (enumValue != null && enumValue.length() <= 2) {
                            prop.vendorExtensions.put("x-rustgen-has-empty-enum", true);
                        }
                    }

                    // add additional enum values that get patched in at the template level
                    if (patchEnumValues.containsKey(model.classname + prop.enumName)) {
                        prop.vendorExtensions.put("x-rustgen-additional-enum-values",
                                patchEnumValues.get(model.classname + prop.enumName));
                    }
                }
            }
        }

        for (Entry<String, Object> entry : objs.entrySet()) {
            String modelName = toModelName(entry.getKey());
            Map<String, Object> inner = (Map<String, Object>) entry.getValue();
            List<Map<String, Object>> models = (List<Map<String, Object>>) inner.get("models");
            for (Map<String, Object> mo : models) {
                CodegenModel cm = (CodegenModel) mo.get("model");
                allModels.put(modelName, cm);
            }
        }


        return newObjs;
    }

    @Override
    public void postProcessModelProperty(CodegenModel model, CodegenProperty property) {
        super.postProcessModelProperty(model, property);

        if (property.items != null) {
            // Recursively handle arrays and objects (Vec and HashMap)
            postProcessModelProperty(model, property.items);
        }

        if (property.datatype.equals("isize")) {
            // needed for windows
            property.datatype = "i64";
        }

        // Handle unknown/generic object types (e.g., from x-go-type extensions)
        // that swagger-codegen generates as "Object"
        if (property.datatype.equals("Object")) {
            property.datatype = "serde_json::Value";
        }

        if (property.dataFormat != null) {
            switch (property.dataFormat) {
                case "uint64":
                    property.datatype = "u64";
                    break;
                case "int64":
                    property.datatype = "i64";
                    break;
                case "uint32":
                    property.datatype = "u32";
                    break;
                case "int32":
                    property.datatype = "i32";
                    break;
                case "uint16":
                    property.datatype = "u16";
                    break;
                case "int16":
                    property.datatype = "i16";
                    break;
                case "uint8":
                    property.datatype = "u8";
                    break;
                case "int8":
                    property.datatype = "i8";
                    break;
            }
        }
    }

    @Override
    public String toEnumVarName(String value, String datatype) {
        String name = super.toEnumVarName(value, datatype);
        if (name.length() == 0) {
            return "EMPTY";
        }
        return name;
    }

    @Override
    public Map<String, Object> postProcessOperations(Map<String, Object> objs) {
        objs = super.postProcessOperations(objs);
        Map<String, Object> operations = (Map<String, Object>) objs.get(
                "operations"
        );
        if (operations != null) {
            List<CodegenOperation> ops = (List<
                    CodegenOperation
                    >) operations.get("operation");
            for (final CodegenOperation operation : ops) {
                if (queryParameterMappings.containsKey(operation.operationIdCamelCase)) {
                    operation.vendorExtensions.put("x-codegen-query-param-legacy-name", queryParameterMappings.get(operation.operationIdCamelCase));
                    for (final CodegenParameter param : operation.queryParams) {
                        if (param.unescapedDescription != null) {
                            String[] splitLines = param.unescapedDescription.split("\n");
                            String[] description = new String[splitLines.length];

                            for (int i = 0, splitLinesLength = splitLines.length; i < splitLinesLength; i++) {
                                String docLine = splitLines[i];
                                description[i] = "    /// " + docLine;
                            }
                            param.unescapedDescription = String.join("\n", description);
                        }
                        if (param.isString) {
                            operation.vendorExtensions.put("x-codegen-query-param-has-string", "true");
                            if (param.defaultValue != null) {
                                param.defaultValue = "String::from(\"" + param.defaultValue + "\")";
                            }
                        }

                        // Special handling for filter parameters
                        if (param.paramName.equals("filters")) {
                            param.isMapContainer = true;
                            param.isString = false;
                            param.isListContainer = true;
                            param.dataType = "&HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>";
                            param.vendorExtensions.put("x-codegen-query-param-struct-type", "HashMap<String, Vec<String>>");
                            operation.vendorExtensions.put("x-codegen-query-param-has-hashmap", "true");
                            param.vendorExtensions.put("x-codegen-query-param-serialize-as-json", "true");
                        }
                        if (!param.paramName.equals(param.baseName)) {
                            param.vendorExtensions.put("x-codegen-query-param-rename", param.baseName);
                        }

                        // Special handling for building images
                        if (operation.operationId.equals("ImageBuild")) {
                            // `buildargs` and `labels` are passed to the Docker server as JSON map
                            if (param.paramName.equals("buildargs") || param.paramName.equals("labels")) {
                                param.isMapContainer = true;
                                param.isString = false;
                                param.isListContainer = false;
                                param.dataType = "&HashMap<impl Into<String> + Clone, impl Into<String> + Clone>";
                                param.vendorExtensions.put("x-codegen-query-param-struct-type", "HashMap<String, String>");
                                param.vendorExtensions.put("x-codegen-query-param-serialize-as-json", "true");
                            }
                            // `cachfrom` is passed to the Docker server as a JSON array
                            if (param.paramName.equals("cachefrom")) {
                                param.isContainer = true;
                                param.isString = false;
                                param.dataType = "&Vec<impl Into<String> + Clone>";
                                param.vendorExtensions.put("x-codegen-query-param-struct-type", "Vec<String>");
                                param.vendorExtensions.put("x-codegen-query-param-serialize-as-json", "true");
                            }
                            // buildkit specific argument
                            if (param.paramName.equals("outputs")) {
                                param.vendorExtensions.put("x-codegen-query-param-is-buildkit", "true");
                                param.dataType = "ImageBuildOutput";
                                param.isString = false;
                                param.defaultValue = null;
                            }
                            // Also toggles buildkit behaviour
                            if (param.paramName.equals("version")) {
                                param.dataType = "BuilderVersion";
                                param.isString = false;
                                param.defaultValue = null;
                                param.required = true;
                            }
                        }

                        // Special handling for creating images
                        if (operation.operationId.equals("ImageCreate")) {
                            if (param.paramName.equals("changes")) {
                                param.vendorExtensions.put("x-codegen-query-param-serialize-join-newlines", "true");
                                param.required = true;

                            }
                        }
                    }

                    // Add buildkit specific 'session' argument, to pass the session ID to the docker engine for subsquent GRPC dialogue
                    if (operation.operationId.equals("ImageBuild")) {
                        CodegenParameter sessionParam = new CodegenParameter();
                        sessionParam.baseName = "session";
                        sessionParam.unescapedDescription = "    /// Session ID used to communicate with Docker's internal buildkit engine";
                        sessionParam.paramName = "session";
                        sessionParam.dataType = "String";
                        sessionParam.isString = true;
                        sessionParam.vendorExtensions = new HashMap<>();
                        sessionParam.vendorExtensions.put("x-codegen-query-param-is-buildkit", "true");
                        operation.queryParams.add(sessionParam);
                    }

                }
            }
        }

        return objs;
    }

}

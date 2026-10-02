// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/*.cs, LGPL-3.0-or-later.

//! Protocol request/response objects.
//!
//! The public API of this module is the curated set of builders, parsers, and value types
//! re-exported below (`build_*`/`parse_*` functions, the `*Response` types, [`PObject`],
//! [`ItemAddress`], the header/notification/alarm types, …). The submodules that define them
//! are crate-internal — depend on the re-exports at `proto::`, not on submodule paths.

pub(crate) mod alarm;
pub(crate) mod create_object;
pub(crate) mod delete_object;
pub(crate) mod explore;
pub(crate) mod get_multi;
pub(crate) mod get_var_substreamed;
pub(crate) mod header;
pub(crate) mod init_ssl;
pub(crate) mod item_address;
pub(crate) mod notification;
pub(crate) mod object;
pub(crate) mod set_multi;
pub(crate) mod set_variable;
pub(crate) mod subscription;
pub(crate) mod system_event;
pub(crate) mod type_info;

pub use alarm::{Alarm, AlarmState, AlarmText, AssociatedValue};
pub use create_object::{
    build_create_session_request, create_session_request_default, parse_create_object_response,
    CreateObjectResponse,
};
pub use delete_object::{build_delete_object_request, parse_delete_object_response};
pub use explore::{build_explore_request, parse_explore_response, ExploreResponse};
pub use get_multi::{build_get_multi_request, parse_get_multi_response, GetMultiVariablesResponse};
pub use get_var_substreamed::{
    build_get_var_substreamed_request, parse_get_var_substreamed_response,
    GetVarSubstreamedResponse,
};
pub use header::{return_value_is_ok, RequestHeader, ResponseHeader};
pub use init_ssl::{
    build_init_ssl_request, init_ssl_request_default, parse_init_ssl_response, InitSslResponse,
};
pub use item_address::{Area, ItemAddress};
pub use notification::{parse_notification, Notification};
pub use object::decode_object_list;
pub use object::PObject;
pub use set_multi::{
    build_session_setup_request, build_set_multi_request, parse_set_multi_response,
    SetMultiVariablesResponse,
};
pub use set_variable::{
    build_set_variable_request, parse_set_variable_response, SetVariableResponse,
};
pub use subscription::{
    build_alarm_subscription_create_request, build_subscription_create_request, SubscriptionItem,
};
pub use system_event::{is_system_event, parse_system_event, SystemEvent};
pub use type_info::{OffsetInfo, VarnameList, VartypeElement, VartypeList};

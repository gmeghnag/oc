// Code generated by protoc-gen-go.
// source: registry.proto
// DO NOT EDIT!

/*
Package api is a generated protocol buffer package.

It is generated from these files:
	registry.proto

It has these top-level messages:
	Channel
	PackageName
	Package
	GroupVersionKind
	Bundle
	ChannelEntry
	ListPackageRequest
	GetPackageRequest
	GetBundleRequest
	GetBundleInChannelRequest
	GetAllReplacementsRequest
	GetReplacementRequest
	GetAllProvidersRequest
	GetLatestProvidersRequest
	GetDefaultProviderRequest
*/
package api

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Channel struct {
	Name    string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	CsvName string `protobuf:"bytes,2,opt,name=csvName" json:"csvName,omitempty"`
}

func (m *Channel) Reset()                    { *m = Channel{} }
func (m *Channel) String() string            { return proto.CompactTextString(m) }
func (*Channel) ProtoMessage()               {}
func (*Channel) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Channel) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Channel) GetCsvName() string {
	if m != nil {
		return m.CsvName
	}
	return ""
}

type PackageName struct {
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

func (m *PackageName) Reset()                    { *m = PackageName{} }
func (m *PackageName) String() string            { return proto.CompactTextString(m) }
func (*PackageName) ProtoMessage()               {}
func (*PackageName) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *PackageName) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type Package struct {
	Name               string     `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Channels           []*Channel `protobuf:"bytes,2,rep,name=channels" json:"channels,omitempty"`
	DefaultChannelName string     `protobuf:"bytes,3,opt,name=defaultChannelName" json:"defaultChannelName,omitempty"`
}

func (m *Package) Reset()                    { *m = Package{} }
func (m *Package) String() string            { return proto.CompactTextString(m) }
func (*Package) ProtoMessage()               {}
func (*Package) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Package) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Package) GetChannels() []*Channel {
	if m != nil {
		return m.Channels
	}
	return nil
}

func (m *Package) GetDefaultChannelName() string {
	if m != nil {
		return m.DefaultChannelName
	}
	return ""
}

type GroupVersionKind struct {
	Group   string `protobuf:"bytes,1,opt,name=group" json:"group,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version" json:"version,omitempty"`
	Kind    string `protobuf:"bytes,3,opt,name=kind" json:"kind,omitempty"`
	Plural  string `protobuf:"bytes,4,opt,name=plural" json:"plural,omitempty"`
}

func (m *GroupVersionKind) Reset()                    { *m = GroupVersionKind{} }
func (m *GroupVersionKind) String() string            { return proto.CompactTextString(m) }
func (*GroupVersionKind) ProtoMessage()               {}
func (*GroupVersionKind) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *GroupVersionKind) GetGroup() string {
	if m != nil {
		return m.Group
	}
	return ""
}

func (m *GroupVersionKind) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *GroupVersionKind) GetKind() string {
	if m != nil {
		return m.Kind
	}
	return ""
}

func (m *GroupVersionKind) GetPlural() string {
	if m != nil {
		return m.Plural
	}
	return ""
}

type Bundle struct {
	CsvName      string              `protobuf:"bytes,1,opt,name=csvName" json:"csvName,omitempty"`
	PackageName  string              `protobuf:"bytes,2,opt,name=packageName" json:"packageName,omitempty"`
	ChannelName  string              `protobuf:"bytes,3,opt,name=channelName" json:"channelName,omitempty"`
	CsvJson      string              `protobuf:"bytes,4,opt,name=csvJson" json:"csvJson,omitempty"`
	Object       []string            `protobuf:"bytes,5,rep,name=object" json:"object,omitempty"`
	BundlePath   string              `protobuf:"bytes,6,opt,name=bundlePath" json:"bundlePath,omitempty"`
	ProvidedApis []*GroupVersionKind `protobuf:"bytes,7,rep,name=providedApis" json:"providedApis,omitempty"`
	RequiredApis []*GroupVersionKind `protobuf:"bytes,8,rep,name=requiredApis" json:"requiredApis,omitempty"`
	Version      string              `protobuf:"bytes,9,opt,name=version" json:"version,omitempty"`
	SkipRange    string              `protobuf:"bytes,10,opt,name=skipRange" json:"skipRange,omitempty"`
}

func (m *Bundle) Reset()                    { *m = Bundle{} }
func (m *Bundle) String() string            { return proto.CompactTextString(m) }
func (*Bundle) ProtoMessage()               {}
func (*Bundle) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Bundle) GetCsvName() string {
	if m != nil {
		return m.CsvName
	}
	return ""
}

func (m *Bundle) GetPackageName() string {
	if m != nil {
		return m.PackageName
	}
	return ""
}

func (m *Bundle) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

func (m *Bundle) GetCsvJson() string {
	if m != nil {
		return m.CsvJson
	}
	return ""
}

func (m *Bundle) GetObject() []string {
	if m != nil {
		return m.Object
	}
	return nil
}

func (m *Bundle) GetBundlePath() string {
	if m != nil {
		return m.BundlePath
	}
	return ""
}

func (m *Bundle) GetProvidedApis() []*GroupVersionKind {
	if m != nil {
		return m.ProvidedApis
	}
	return nil
}

func (m *Bundle) GetRequiredApis() []*GroupVersionKind {
	if m != nil {
		return m.RequiredApis
	}
	return nil
}

func (m *Bundle) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *Bundle) GetSkipRange() string {
	if m != nil {
		return m.SkipRange
	}
	return ""
}

type ChannelEntry struct {
	PackageName string `protobuf:"bytes,1,opt,name=packageName" json:"packageName,omitempty"`
	ChannelName string `protobuf:"bytes,2,opt,name=channelName" json:"channelName,omitempty"`
	BundleName  string `protobuf:"bytes,3,opt,name=bundleName" json:"bundleName,omitempty"`
	Replaces    string `protobuf:"bytes,4,opt,name=replaces" json:"replaces,omitempty"`
}

func (m *ChannelEntry) Reset()                    { *m = ChannelEntry{} }
func (m *ChannelEntry) String() string            { return proto.CompactTextString(m) }
func (*ChannelEntry) ProtoMessage()               {}
func (*ChannelEntry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ChannelEntry) GetPackageName() string {
	if m != nil {
		return m.PackageName
	}
	return ""
}

func (m *ChannelEntry) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

func (m *ChannelEntry) GetBundleName() string {
	if m != nil {
		return m.BundleName
	}
	return ""
}

func (m *ChannelEntry) GetReplaces() string {
	if m != nil {
		return m.Replaces
	}
	return ""
}

type ListPackageRequest struct {
}

func (m *ListPackageRequest) Reset()                    { *m = ListPackageRequest{} }
func (m *ListPackageRequest) String() string            { return proto.CompactTextString(m) }
func (*ListPackageRequest) ProtoMessage()               {}
func (*ListPackageRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

type GetPackageRequest struct {
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

func (m *GetPackageRequest) Reset()                    { *m = GetPackageRequest{} }
func (m *GetPackageRequest) String() string            { return proto.CompactTextString(m) }
func (*GetPackageRequest) ProtoMessage()               {}
func (*GetPackageRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *GetPackageRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type GetBundleRequest struct {
	PkgName     string `protobuf:"bytes,1,opt,name=pkgName" json:"pkgName,omitempty"`
	ChannelName string `protobuf:"bytes,2,opt,name=channelName" json:"channelName,omitempty"`
	CsvName     string `protobuf:"bytes,3,opt,name=csvName" json:"csvName,omitempty"`
}

func (m *GetBundleRequest) Reset()                    { *m = GetBundleRequest{} }
func (m *GetBundleRequest) String() string            { return proto.CompactTextString(m) }
func (*GetBundleRequest) ProtoMessage()               {}
func (*GetBundleRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *GetBundleRequest) GetPkgName() string {
	if m != nil {
		return m.PkgName
	}
	return ""
}

func (m *GetBundleRequest) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

func (m *GetBundleRequest) GetCsvName() string {
	if m != nil {
		return m.CsvName
	}
	return ""
}

type GetBundleInChannelRequest struct {
	PkgName     string `protobuf:"bytes,1,opt,name=pkgName" json:"pkgName,omitempty"`
	ChannelName string `protobuf:"bytes,2,opt,name=channelName" json:"channelName,omitempty"`
}

func (m *GetBundleInChannelRequest) Reset()                    { *m = GetBundleInChannelRequest{} }
func (m *GetBundleInChannelRequest) String() string            { return proto.CompactTextString(m) }
func (*GetBundleInChannelRequest) ProtoMessage()               {}
func (*GetBundleInChannelRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *GetBundleInChannelRequest) GetPkgName() string {
	if m != nil {
		return m.PkgName
	}
	return ""
}

func (m *GetBundleInChannelRequest) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

type GetAllReplacementsRequest struct {
	CsvName string `protobuf:"bytes,1,opt,name=csvName" json:"csvName,omitempty"`
}

func (m *GetAllReplacementsRequest) Reset()                    { *m = GetAllReplacementsRequest{} }
func (m *GetAllReplacementsRequest) String() string            { return proto.CompactTextString(m) }
func (*GetAllReplacementsRequest) ProtoMessage()               {}
func (*GetAllReplacementsRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *GetAllReplacementsRequest) GetCsvName() string {
	if m != nil {
		return m.CsvName
	}
	return ""
}

type GetReplacementRequest struct {
	CsvName     string `protobuf:"bytes,1,opt,name=csvName" json:"csvName,omitempty"`
	PkgName     string `protobuf:"bytes,2,opt,name=pkgName" json:"pkgName,omitempty"`
	ChannelName string `protobuf:"bytes,3,opt,name=channelName" json:"channelName,omitempty"`
}

func (m *GetReplacementRequest) Reset()                    { *m = GetReplacementRequest{} }
func (m *GetReplacementRequest) String() string            { return proto.CompactTextString(m) }
func (*GetReplacementRequest) ProtoMessage()               {}
func (*GetReplacementRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *GetReplacementRequest) GetCsvName() string {
	if m != nil {
		return m.CsvName
	}
	return ""
}

func (m *GetReplacementRequest) GetPkgName() string {
	if m != nil {
		return m.PkgName
	}
	return ""
}

func (m *GetReplacementRequest) GetChannelName() string {
	if m != nil {
		return m.ChannelName
	}
	return ""
}

type GetAllProvidersRequest struct {
	Group   string `protobuf:"bytes,1,opt,name=group" json:"group,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version" json:"version,omitempty"`
	Kind    string `protobuf:"bytes,3,opt,name=kind" json:"kind,omitempty"`
	Plural  string `protobuf:"bytes,4,opt,name=plural" json:"plural,omitempty"`
}

func (m *GetAllProvidersRequest) Reset()                    { *m = GetAllProvidersRequest{} }
func (m *GetAllProvidersRequest) String() string            { return proto.CompactTextString(m) }
func (*GetAllProvidersRequest) ProtoMessage()               {}
func (*GetAllProvidersRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *GetAllProvidersRequest) GetGroup() string {
	if m != nil {
		return m.Group
	}
	return ""
}

func (m *GetAllProvidersRequest) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *GetAllProvidersRequest) GetKind() string {
	if m != nil {
		return m.Kind
	}
	return ""
}

func (m *GetAllProvidersRequest) GetPlural() string {
	if m != nil {
		return m.Plural
	}
	return ""
}

type GetLatestProvidersRequest struct {
	Group   string `protobuf:"bytes,1,opt,name=group" json:"group,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version" json:"version,omitempty"`
	Kind    string `protobuf:"bytes,3,opt,name=kind" json:"kind,omitempty"`
	Plural  string `protobuf:"bytes,4,opt,name=plural" json:"plural,omitempty"`
}

func (m *GetLatestProvidersRequest) Reset()                    { *m = GetLatestProvidersRequest{} }
func (m *GetLatestProvidersRequest) String() string            { return proto.CompactTextString(m) }
func (*GetLatestProvidersRequest) ProtoMessage()               {}
func (*GetLatestProvidersRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

func (m *GetLatestProvidersRequest) GetGroup() string {
	if m != nil {
		return m.Group
	}
	return ""
}

func (m *GetLatestProvidersRequest) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *GetLatestProvidersRequest) GetKind() string {
	if m != nil {
		return m.Kind
	}
	return ""
}

func (m *GetLatestProvidersRequest) GetPlural() string {
	if m != nil {
		return m.Plural
	}
	return ""
}

type GetDefaultProviderRequest struct {
	Group   string `protobuf:"bytes,1,opt,name=group" json:"group,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version" json:"version,omitempty"`
	Kind    string `protobuf:"bytes,3,opt,name=kind" json:"kind,omitempty"`
	Plural  string `protobuf:"bytes,4,opt,name=plural" json:"plural,omitempty"`
}

func (m *GetDefaultProviderRequest) Reset()                    { *m = GetDefaultProviderRequest{} }
func (m *GetDefaultProviderRequest) String() string            { return proto.CompactTextString(m) }
func (*GetDefaultProviderRequest) ProtoMessage()               {}
func (*GetDefaultProviderRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func (m *GetDefaultProviderRequest) GetGroup() string {
	if m != nil {
		return m.Group
	}
	return ""
}

func (m *GetDefaultProviderRequest) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *GetDefaultProviderRequest) GetKind() string {
	if m != nil {
		return m.Kind
	}
	return ""
}

func (m *GetDefaultProviderRequest) GetPlural() string {
	if m != nil {
		return m.Plural
	}
	return ""
}

func init() {
	proto.RegisterType((*Channel)(nil), "api.Channel")
	proto.RegisterType((*PackageName)(nil), "api.PackageName")
	proto.RegisterType((*Package)(nil), "api.Package")
	proto.RegisterType((*GroupVersionKind)(nil), "api.GroupVersionKind")
	proto.RegisterType((*Bundle)(nil), "api.Bundle")
	proto.RegisterType((*ChannelEntry)(nil), "api.ChannelEntry")
	proto.RegisterType((*ListPackageRequest)(nil), "api.ListPackageRequest")
	proto.RegisterType((*GetPackageRequest)(nil), "api.GetPackageRequest")
	proto.RegisterType((*GetBundleRequest)(nil), "api.GetBundleRequest")
	proto.RegisterType((*GetBundleInChannelRequest)(nil), "api.GetBundleInChannelRequest")
	proto.RegisterType((*GetAllReplacementsRequest)(nil), "api.GetAllReplacementsRequest")
	proto.RegisterType((*GetReplacementRequest)(nil), "api.GetReplacementRequest")
	proto.RegisterType((*GetAllProvidersRequest)(nil), "api.GetAllProvidersRequest")
	proto.RegisterType((*GetLatestProvidersRequest)(nil), "api.GetLatestProvidersRequest")
	proto.RegisterType((*GetDefaultProviderRequest)(nil), "api.GetDefaultProviderRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Registry service

type RegistryClient interface {
	ListPackages(ctx context.Context, in *ListPackageRequest, opts ...grpc.CallOption) (Registry_ListPackagesClient, error)
	GetPackage(ctx context.Context, in *GetPackageRequest, opts ...grpc.CallOption) (*Package, error)
	GetBundle(ctx context.Context, in *GetBundleRequest, opts ...grpc.CallOption) (*Bundle, error)
	GetBundleForChannel(ctx context.Context, in *GetBundleInChannelRequest, opts ...grpc.CallOption) (*Bundle, error)
	GetChannelEntriesThatReplace(ctx context.Context, in *GetAllReplacementsRequest, opts ...grpc.CallOption) (Registry_GetChannelEntriesThatReplaceClient, error)
	GetBundleThatReplaces(ctx context.Context, in *GetReplacementRequest, opts ...grpc.CallOption) (*Bundle, error)
	GetChannelEntriesThatProvide(ctx context.Context, in *GetAllProvidersRequest, opts ...grpc.CallOption) (Registry_GetChannelEntriesThatProvideClient, error)
	GetLatestChannelEntriesThatProvide(ctx context.Context, in *GetLatestProvidersRequest, opts ...grpc.CallOption) (Registry_GetLatestChannelEntriesThatProvideClient, error)
	GetDefaultBundleThatProvides(ctx context.Context, in *GetDefaultProviderRequest, opts ...grpc.CallOption) (*Bundle, error)
}

type registryClient struct {
	cc *grpc.ClientConn
}

func NewRegistryClient(cc *grpc.ClientConn) RegistryClient {
	return &registryClient{cc}
}

func (c *registryClient) ListPackages(ctx context.Context, in *ListPackageRequest, opts ...grpc.CallOption) (Registry_ListPackagesClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_Registry_serviceDesc.Streams[0], c.cc, "/api.Registry/ListPackages", opts...)
	if err != nil {
		return nil, err
	}
	x := &registryListPackagesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Registry_ListPackagesClient interface {
	Recv() (*PackageName, error)
	grpc.ClientStream
}

type registryListPackagesClient struct {
	grpc.ClientStream
}

func (x *registryListPackagesClient) Recv() (*PackageName, error) {
	m := new(PackageName)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *registryClient) GetPackage(ctx context.Context, in *GetPackageRequest, opts ...grpc.CallOption) (*Package, error) {
	out := new(Package)
	err := grpc.Invoke(ctx, "/api.Registry/GetPackage", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetBundle(ctx context.Context, in *GetBundleRequest, opts ...grpc.CallOption) (*Bundle, error) {
	out := new(Bundle)
	err := grpc.Invoke(ctx, "/api.Registry/GetBundle", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetBundleForChannel(ctx context.Context, in *GetBundleInChannelRequest, opts ...grpc.CallOption) (*Bundle, error) {
	out := new(Bundle)
	err := grpc.Invoke(ctx, "/api.Registry/GetBundleForChannel", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetChannelEntriesThatReplace(ctx context.Context, in *GetAllReplacementsRequest, opts ...grpc.CallOption) (Registry_GetChannelEntriesThatReplaceClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_Registry_serviceDesc.Streams[1], c.cc, "/api.Registry/GetChannelEntriesThatReplace", opts...)
	if err != nil {
		return nil, err
	}
	x := &registryGetChannelEntriesThatReplaceClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Registry_GetChannelEntriesThatReplaceClient interface {
	Recv() (*ChannelEntry, error)
	grpc.ClientStream
}

type registryGetChannelEntriesThatReplaceClient struct {
	grpc.ClientStream
}

func (x *registryGetChannelEntriesThatReplaceClient) Recv() (*ChannelEntry, error) {
	m := new(ChannelEntry)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *registryClient) GetBundleThatReplaces(ctx context.Context, in *GetReplacementRequest, opts ...grpc.CallOption) (*Bundle, error) {
	out := new(Bundle)
	err := grpc.Invoke(ctx, "/api.Registry/GetBundleThatReplaces", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetChannelEntriesThatProvide(ctx context.Context, in *GetAllProvidersRequest, opts ...grpc.CallOption) (Registry_GetChannelEntriesThatProvideClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_Registry_serviceDesc.Streams[2], c.cc, "/api.Registry/GetChannelEntriesThatProvide", opts...)
	if err != nil {
		return nil, err
	}
	x := &registryGetChannelEntriesThatProvideClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Registry_GetChannelEntriesThatProvideClient interface {
	Recv() (*ChannelEntry, error)
	grpc.ClientStream
}

type registryGetChannelEntriesThatProvideClient struct {
	grpc.ClientStream
}

func (x *registryGetChannelEntriesThatProvideClient) Recv() (*ChannelEntry, error) {
	m := new(ChannelEntry)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *registryClient) GetLatestChannelEntriesThatProvide(ctx context.Context, in *GetLatestProvidersRequest, opts ...grpc.CallOption) (Registry_GetLatestChannelEntriesThatProvideClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_Registry_serviceDesc.Streams[3], c.cc, "/api.Registry/GetLatestChannelEntriesThatProvide", opts...)
	if err != nil {
		return nil, err
	}
	x := &registryGetLatestChannelEntriesThatProvideClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Registry_GetLatestChannelEntriesThatProvideClient interface {
	Recv() (*ChannelEntry, error)
	grpc.ClientStream
}

type registryGetLatestChannelEntriesThatProvideClient struct {
	grpc.ClientStream
}

func (x *registryGetLatestChannelEntriesThatProvideClient) Recv() (*ChannelEntry, error) {
	m := new(ChannelEntry)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *registryClient) GetDefaultBundleThatProvides(ctx context.Context, in *GetDefaultProviderRequest, opts ...grpc.CallOption) (*Bundle, error) {
	out := new(Bundle)
	err := grpc.Invoke(ctx, "/api.Registry/GetDefaultBundleThatProvides", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Registry service

type RegistryServer interface {
	ListPackages(*ListPackageRequest, Registry_ListPackagesServer) error
	GetPackage(context.Context, *GetPackageRequest) (*Package, error)
	GetBundle(context.Context, *GetBundleRequest) (*Bundle, error)
	GetBundleForChannel(context.Context, *GetBundleInChannelRequest) (*Bundle, error)
	GetChannelEntriesThatReplace(*GetAllReplacementsRequest, Registry_GetChannelEntriesThatReplaceServer) error
	GetBundleThatReplaces(context.Context, *GetReplacementRequest) (*Bundle, error)
	GetChannelEntriesThatProvide(*GetAllProvidersRequest, Registry_GetChannelEntriesThatProvideServer) error
	GetLatestChannelEntriesThatProvide(*GetLatestProvidersRequest, Registry_GetLatestChannelEntriesThatProvideServer) error
	GetDefaultBundleThatProvides(context.Context, *GetDefaultProviderRequest) (*Bundle, error)
}

func RegisterRegistryServer(s *grpc.Server, srv RegistryServer) {
	s.RegisterService(&_Registry_serviceDesc, srv)
}

func _Registry_ListPackages_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ListPackageRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RegistryServer).ListPackages(m, &registryListPackagesServer{stream})
}

type Registry_ListPackagesServer interface {
	Send(*PackageName) error
	grpc.ServerStream
}

type registryListPackagesServer struct {
	grpc.ServerStream
}

func (x *registryListPackagesServer) Send(m *PackageName) error {
	return x.ServerStream.SendMsg(m)
}

func _Registry_GetPackage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPackageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetPackage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Registry/GetPackage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetPackage(ctx, req.(*GetPackageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetBundle_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBundleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetBundle(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Registry/GetBundle",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetBundle(ctx, req.(*GetBundleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetBundleForChannel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBundleInChannelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetBundleForChannel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Registry/GetBundleForChannel",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetBundleForChannel(ctx, req.(*GetBundleInChannelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetChannelEntriesThatReplace_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetAllReplacementsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RegistryServer).GetChannelEntriesThatReplace(m, &registryGetChannelEntriesThatReplaceServer{stream})
}

type Registry_GetChannelEntriesThatReplaceServer interface {
	Send(*ChannelEntry) error
	grpc.ServerStream
}

type registryGetChannelEntriesThatReplaceServer struct {
	grpc.ServerStream
}

func (x *registryGetChannelEntriesThatReplaceServer) Send(m *ChannelEntry) error {
	return x.ServerStream.SendMsg(m)
}

func _Registry_GetBundleThatReplaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetReplacementRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetBundleThatReplaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Registry/GetBundleThatReplaces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetBundleThatReplaces(ctx, req.(*GetReplacementRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetChannelEntriesThatProvide_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetAllProvidersRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RegistryServer).GetChannelEntriesThatProvide(m, &registryGetChannelEntriesThatProvideServer{stream})
}

type Registry_GetChannelEntriesThatProvideServer interface {
	Send(*ChannelEntry) error
	grpc.ServerStream
}

type registryGetChannelEntriesThatProvideServer struct {
	grpc.ServerStream
}

func (x *registryGetChannelEntriesThatProvideServer) Send(m *ChannelEntry) error {
	return x.ServerStream.SendMsg(m)
}

func _Registry_GetLatestChannelEntriesThatProvide_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetLatestProvidersRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RegistryServer).GetLatestChannelEntriesThatProvide(m, &registryGetLatestChannelEntriesThatProvideServer{stream})
}

type Registry_GetLatestChannelEntriesThatProvideServer interface {
	Send(*ChannelEntry) error
	grpc.ServerStream
}

type registryGetLatestChannelEntriesThatProvideServer struct {
	grpc.ServerStream
}

func (x *registryGetLatestChannelEntriesThatProvideServer) Send(m *ChannelEntry) error {
	return x.ServerStream.SendMsg(m)
}

func _Registry_GetDefaultBundleThatProvides_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDefaultProviderRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetDefaultBundleThatProvides(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Registry/GetDefaultBundleThatProvides",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetDefaultBundleThatProvides(ctx, req.(*GetDefaultProviderRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Registry_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.Registry",
	HandlerType: (*RegistryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPackage",
			Handler:    _Registry_GetPackage_Handler,
		},
		{
			MethodName: "GetBundle",
			Handler:    _Registry_GetBundle_Handler,
		},
		{
			MethodName: "GetBundleForChannel",
			Handler:    _Registry_GetBundleForChannel_Handler,
		},
		{
			MethodName: "GetBundleThatReplaces",
			Handler:    _Registry_GetBundleThatReplaces_Handler,
		},
		{
			MethodName: "GetDefaultBundleThatProvides",
			Handler:    _Registry_GetDefaultBundleThatProvides_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ListPackages",
			Handler:       _Registry_ListPackages_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetChannelEntriesThatReplace",
			Handler:       _Registry_GetChannelEntriesThatReplace_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetChannelEntriesThatProvide",
			Handler:       _Registry_GetChannelEntriesThatProvide_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetLatestChannelEntriesThatProvide",
			Handler:       _Registry_GetLatestChannelEntriesThatProvide_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "registry.proto",
}

func init() { proto.RegisterFile("registry.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 701 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xc4, 0x56, 0x5d, 0x6f, 0xd3, 0x3c,
	0x14, 0x5e, 0xdb, 0xad, 0x1f, 0xa7, 0xd5, 0xab, 0xcd, 0xef, 0x36, 0x42, 0x99, 0xa6, 0xe2, 0x1b,
	0x76, 0x55, 0xc1, 0x00, 0x21, 0x2e, 0xb8, 0xd8, 0x18, 0x54, 0xc0, 0x40, 0x53, 0xc4, 0xc7, 0x05,
	0x57, 0x5e, 0x6b, 0x5a, 0xd3, 0xcc, 0xc9, 0x6c, 0x67, 0xd3, 0xfe, 0x04, 0x37, 0xfc, 0x47, 0x7e,
	0x07, 0x8a, 0xed, 0x24, 0x4e, 0x9a, 0x6e, 0x48, 0x08, 0xb8, 0xeb, 0x39, 0x3e, 0x1f, 0xcf, 0x79,
	0x72, 0x1e, 0xbb, 0xf0, 0x9f, 0xa0, 0x53, 0x26, 0x95, 0xb8, 0x1a, 0x46, 0x22, 0x54, 0x21, 0x6a,
	0x90, 0x88, 0xe1, 0x27, 0xd0, 0x7a, 0x3e, 0x23, 0x9c, 0xd3, 0x00, 0x21, 0x58, 0xe5, 0xe4, 0x8c,
	0x7a, 0xb5, 0x41, 0x6d, 0xaf, 0xe3, 0xeb, 0xdf, 0xc8, 0x83, 0xd6, 0x58, 0x5e, 0xbc, 0x4b, 0xdc,
	0x75, 0xed, 0x4e, 0x4d, 0x7c, 0x17, 0xba, 0x27, 0x64, 0x3c, 0x27, 0x53, 0x9a, 0x98, 0x55, 0xc9,
	0xf8, 0x12, 0x5a, 0x36, 0xa4, 0xb2, 0xf6, 0x1e, 0xb4, 0xc7, 0xa6, 0xb5, 0xf4, 0xea, 0x83, 0xc6,
	0x5e, 0x77, 0xbf, 0x37, 0x24, 0x11, 0x1b, 0x5a, 0x3c, 0x7e, 0x76, 0x8a, 0x86, 0x80, 0x26, 0xf4,
	0x0b, 0x89, 0x03, 0x65, 0xcf, 0x34, 0xa0, 0x86, 0xae, 0x55, 0x71, 0x82, 0x39, 0xac, 0x8f, 0x44,
	0x18, 0x47, 0x1f, 0xa9, 0x90, 0x2c, 0xe4, 0x6f, 0x18, 0x9f, 0xa0, 0x4d, 0x58, 0x9b, 0x26, 0x3e,
	0x0b, 0xc1, 0x18, 0xc9, 0x7c, 0x17, 0x26, 0x28, 0x9d, 0xcf, 0x9a, 0x09, 0xe2, 0x39, 0xe3, 0x13,
	0xdb, 0x45, 0xff, 0x46, 0xdb, 0xd0, 0x8c, 0x82, 0x58, 0x90, 0xc0, 0x5b, 0xd5, 0x5e, 0x6b, 0xe1,
	0x1f, 0x75, 0x68, 0x1e, 0xc6, 0x7c, 0x12, 0x14, 0x08, 0xab, 0x15, 0x08, 0x43, 0x03, 0xe8, 0x46,
	0x39, 0x61, 0xb6, 0x9d, 0xeb, 0x4a, 0x22, 0xc6, 0x0b, 0xf3, 0xb9, 0x2e, 0x5b, 0xfd, 0xb5, 0x0c,
	0xb9, 0x45, 0x90, 0x9a, 0x09, 0xb4, 0xf0, 0xf4, 0x2b, 0x1d, 0x2b, 0x6f, 0x6d, 0xd0, 0x48, 0xa0,
	0x19, 0x0b, 0xed, 0x02, 0x9c, 0x6a, 0x64, 0x27, 0x44, 0xcd, 0xbc, 0xa6, 0x4e, 0x72, 0x3c, 0xe8,
	0x29, 0xf4, 0x22, 0x11, 0x5e, 0xb0, 0x09, 0x9d, 0x1c, 0x44, 0x4c, 0x7a, 0x2d, 0xfd, 0x21, 0xb6,
	0xf4, 0x87, 0x28, 0x73, 0xe8, 0x17, 0x42, 0x93, 0x54, 0x41, 0xcf, 0x63, 0x26, 0x6c, 0x6a, 0xfb,
	0xda, 0x54, 0x37, 0xd4, 0xa5, 0xbd, 0x53, 0xa4, 0x7d, 0x07, 0x3a, 0x72, 0xce, 0x22, 0x9f, 0xf0,
	0x29, 0xf5, 0x40, 0x9f, 0xe5, 0x0e, 0xfc, 0xad, 0x06, 0x3d, 0xfb, 0xa1, 0x5f, 0x70, 0x25, 0xae,
	0xca, 0xa4, 0xd6, 0x6e, 0x24, 0xb5, 0xbe, 0x48, 0x6a, 0x46, 0x91, 0xc3, 0xba, 0xe3, 0x41, 0x7d,
	0x68, 0x0b, 0x1a, 0x05, 0x64, 0x4c, 0xa5, 0x65, 0x3d, 0xb3, 0xf1, 0x26, 0xa0, 0x63, 0x26, 0x95,
	0x5d, 0x73, 0x9f, 0x9e, 0xc7, 0x54, 0x2a, 0x7c, 0x0f, 0x36, 0x46, 0xb4, 0xe4, 0xac, 0x54, 0xc8,
	0x0c, 0xd6, 0x47, 0x54, 0x99, 0xd5, 0x49, 0xe3, 0x3c, 0x68, 0x45, 0xf3, 0xa9, 0xbb, 0x41, 0xd6,
	0xfc, 0x85, 0x51, 0x9c, 0xed, 0x6b, 0x14, 0xe5, 0xfa, 0x09, 0x6e, 0x67, 0x9d, 0x5e, 0xf1, 0x54,
	0x62, 0xbf, 0xdf, 0x12, 0x3f, 0xd6, 0x85, 0x0f, 0x82, 0xc0, 0x37, 0x9c, 0x9c, 0x51, 0xae, 0xa4,
	0x53, 0xb8, 0x5a, 0x0d, 0xf8, 0x0c, 0xb6, 0x46, 0x54, 0x39, 0x39, 0x37, 0xa6, 0xb8, 0x28, 0xeb,
	0xd7, 0xa2, 0x5c, 0x14, 0x0e, 0x56, 0xb0, 0x6d, 0x50, 0x9e, 0x98, 0x0d, 0x16, 0x19, 0xc4, 0x3f,
	0x79, 0x2f, 0x5c, 0x6a, 0x6e, 0x8e, 0x89, 0xa2, 0x52, 0xfd, 0x83, 0xc6, 0x47, 0xe6, 0x66, 0x4c,
	0x3b, 0xff, 0x85, 0xc6, 0xfb, 0xdf, 0xd7, 0xa0, 0xed, 0xdb, 0x67, 0x06, 0x3d, 0x83, 0x9e, 0x23,
	0x0e, 0x89, 0x6e, 0xe9, 0xab, 0x61, 0x51, 0x2f, 0xfd, 0x75, 0x7d, 0xe0, 0x3c, 0x27, 0x78, 0xe5,
	0x7e, 0x0d, 0x3d, 0x02, 0xc8, 0x55, 0x84, 0xb6, 0xcd, 0xbd, 0x52, 0x96, 0x55, 0xbf, 0xe7, 0xe6,
	0xe2, 0x15, 0xf4, 0x00, 0x3a, 0xd9, 0xa2, 0xa3, 0xad, 0x34, 0xa9, 0x20, 0xb1, 0x7e, 0x57, 0xbb,
	0x8d, 0x0f, 0xaf, 0xa0, 0x23, 0xf8, 0x3f, 0x0b, 0x79, 0x19, 0x8a, 0xf4, 0x3d, 0xdc, 0x2d, 0x26,
	0x97, 0x55, 0x53, 0xae, 0xf2, 0x01, 0x76, 0x46, 0x54, 0x39, 0xb7, 0x13, 0xa3, 0xf2, 0xfd, 0x8c,
	0xa4, 0x3b, 0x9e, 0x97, 0xab, 0xd6, 0x4a, 0x7f, 0xc3, 0x7d, 0xfc, 0xf4, 0xed, 0xa6, 0x59, 0x38,
	0xd4, 0x42, 0x31, 0x5d, 0x9c, 0x72, 0x12, 0xf5, 0xd3, 0x7a, 0x8b, 0x22, 0x2a, 0x43, 0xf3, 0x97,
	0x40, 0xb3, 0x9b, 0x81, 0xee, 0x38, 0xd0, 0xca, 0x7b, 0xba, 0x0c, 0xd7, 0x67, 0xc0, 0xd9, 0x6e,
	0x2f, 0xaf, 0x9c, 0x0d, 0x5d, 0x2d, 0x82, 0x65, 0xc5, 0xdf, 0x6a, 0xc0, 0x76, 0x7f, 0xf3, 0xd9,
	0x6d, 0xba, 0xcc, 0xcb, 0x56, 0xaf, 0x78, 0x69, 0xfe, 0xd3, 0xa6, 0xfe, 0xc3, 0xf3, 0xf0, 0x67,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xe1, 0x3c, 0x83, 0x36, 0x02, 0x09, 0x00, 0x00,
}
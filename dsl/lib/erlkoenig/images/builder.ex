defmodule Erlkoenig.Images.Builder do
  @moduledoc """
  Accumulates global image declarations.

  Images are EROFS files built externally (mkfs.erofs) and referenced
  by name from container definitions. One image can serve multiple
  containers across multiple zones.
  """

  defstruct images: []

  def new, do: %__MODULE__{}

  def add_image(%__MODULE__{images: imgs} = b, name, opts) do
    path = Keyword.fetch!(opts, :path)
    entry = %{name: to_string(name), path: to_string(path)}

    # Compile-time: reject duplicates
    if Enum.any?(imgs, fn i -> i.name == entry.name end) do
      raise CompileError,
        description: "duplicate image name: #{inspect(name)}"
    end

    %{b | images: imgs ++ [entry]}
  end

  def to_term(%__MODULE__{images: imgs}) do
    Map.new(imgs, fn %{name: n, path: p} -> {n, p} end)
  end

  def image_names(%__MODULE__{images: imgs}) do
    Enum.map(imgs, & &1.name)
  end

  def resolve_path(%__MODULE__{images: imgs}, name) do
    case Enum.find(imgs, fn i -> i.name == to_string(name) end) do
      %{path: p} -> {:ok, p}
      nil -> {:error, {:undeclared_image, name}}
    end
  end
end

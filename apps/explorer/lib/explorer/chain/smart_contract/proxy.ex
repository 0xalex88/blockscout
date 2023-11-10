defmodule Explorer.Chain.SmartContract.Proxy do
  @moduledoc """
  Module for proxy smart-contract implementation detection
  """

  alias Explorer.Chain
  alias Explorer.Chain.{Hash, SmartContract}
  alias Explorer.Chain.SmartContract.Proxy
  alias Explorer.Chain.SmartContract.Proxy.{Basic, EIP1167, EIP1967, MasterCopy}

  # supported signatures:
  # 5c60da1b = keccak256(implementation())
  @implementation_signature "5c60da1b"
  # aaf10f42 = keccak256(getImplementation())
  @get_implementation_signature "aaf10f42"

  @burn_address_hash_string_32 "0x0000000000000000000000000000000000000000000000000000000000000000"

  @typep api? :: {:api?, true | false}

  defguard is_burn_signature(term) when term in ["0x", "0x0", @burn_address_hash_string_32]

  @doc """
  Fetches into DB proxy contract implementation's address and name from different proxy patterns
  """
  @spec fetch_implementation_address_hash(Hash.Address.t(), list(), boolean() | nil, [api?]) ::
          {String.t() | nil, String.t() | nil}
  def fetch_implementation_address_hash(proxy_address_hash, abi, metadata_from_verified_twin, options)
      when not is_nil(proxy_address_hash) and not is_nil(abi) do
    implementation_method_abi = get_naive_implementation_abi(abi, "implementation")

    get_implementation_method_abi = get_naive_implementation_abi(abi, "getImplementation")

    master_copy_method_abi = get_master_copy_pattern(abi)

    implementation_address =
      cond do
        implementation_method_abi ->
          Basic.get_implementation_address(@implementation_signature, proxy_address_hash, abi)

        get_implementation_method_abi ->
          Basic.get_implementation_address(@get_implementation_signature, proxy_address_hash, abi)

        master_copy_method_abi ->
          MasterCopy.get_implementation_address(proxy_address_hash)

        true ->
          EIP1967.get_implementation_address(proxy_address_hash) ||
            EIP1167.get_implementation_address(proxy_address_hash)
      end

    SmartContract.save_implementation_data(
      implementation_address,
      proxy_address_hash,
      metadata_from_verified_twin,
      options
    )
  end

  def fetch_implementation_address_hash(_proxy_address_hash, _abi, _, _) do
    {nil, nil}
  end

  defp get_naive_implementation_abi(abi, getter_name) do
    abi
    |> Enum.find(fn method ->
      Map.get(method, "name") == getter_name && Map.get(method, "stateMutability") == "view"
    end)
  end

  def abi_decode_address_output(nil), do: nil

  def abi_decode_address_output("0x"), do: SmartContract.burn_address_hash_string()

  def abi_decode_address_output(address) when is_binary(address) do
    if String.length(address) > 42 do
      "0x" <> String.slice(address, -40, 40)
    else
      address
    end
  end

  def abi_decode_address_output(_), do: nil

  def get_implementation_abi(implementation_address_hash_string, options \\ [])

  def get_implementation_abi(implementation_address_hash_string, options)
      when not is_nil(implementation_address_hash_string) do
    case Chain.string_to_address_hash(implementation_address_hash_string) do
      {:ok, implementation_address_hash} ->
        implementation_smart_contract =
          implementation_address_hash
          |> SmartContract.address_hash_to_smart_contract(options)

        if implementation_smart_contract do
          implementation_smart_contract
          |> Map.get(:abi)
        else
          []
        end

      _ ->
        []
    end
  end

  def get_implementation_abi(implementation_address_hash_string, _) when is_nil(implementation_address_hash_string) do
    []
  end

  def get_implementation_abi_from_proxy(
        %SmartContract{address_hash: proxy_address_hash, abi: abi} = smart_contract,
        options
      )
      when not is_nil(proxy_address_hash) and not is_nil(abi) do
    {implementation_address_hash_string, _name} = SmartContract.get_implementation_address_hash(smart_contract, options)
    get_implementation_abi(implementation_address_hash_string)
  end

  def get_implementation_abi_from_proxy(_, _), do: []

  def gnosis_safe_contract?(abi) when not is_nil(abi) do
    if get_master_copy_pattern(abi), do: true, else: false
  end

  def gnosis_safe_contract?(abi) when is_nil(abi), do: false

  def master_copy_pattern?(method) do
    Map.get(method, "type") == "constructor" &&
      method
      |> Enum.find(fn item ->
        case item do
          {"inputs", inputs} ->
            find_input_by_name(inputs, "_masterCopy") || find_input_by_name(inputs, "_singleton")

          _ ->
            false
        end
      end)
  end

  defp get_master_copy_pattern(abi) do
    abi
    |> Enum.find(fn method ->
      master_copy_pattern?(method)
    end)
  end

  def combine_proxy_implementation_abi(smart_contract, options \\ [])

  def combine_proxy_implementation_abi(%SmartContract{abi: abi} = smart_contract, options) when not is_nil(abi) do
    implementation_abi = Proxy.get_implementation_abi_from_proxy(smart_contract, options)

    if Enum.empty?(implementation_abi), do: abi, else: implementation_abi ++ abi
  end

  def combine_proxy_implementation_abi(_, _) do
    []
  end

  defp find_input_by_name(inputs, name) do
    inputs
    |> Enum.find(fn input ->
      Map.get(input, "name") == name
    end)
  end
end
